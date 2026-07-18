import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { ATTACKERS } from "./runner.js";
import type { AttackClass } from "./types.js";

// The hunt's FREE deterministic pre-filter. Given a repo, it scans every source file for each
// lane's static sink pattern (reusing the very SINK_RE the gate drives) and ranks files by sink
// density. NO sandbox, NO LLM, NO execution — a lead is only a place to point the (expensive)
// prove phase, never a finding. This is the cost control the crabbox lesson demands: the
// deterministic sweep is free, so the LLM+sandbox fan-out only ever touches the density head.

const SOURCE_EXTS = ["ts", "mts", "cts", "js", "cjs", "mjs", "cs", "swift"];
// Exclude tests/fixtures/build output/vendored code — same spirit as the gate's scope.
const SKIP_RE =
  /(\.test\.|\.spec\.|-harness\.|(^|\/)test-support\/|(^|\/)tests?\/|(^|\/)__tests__\/|(^|\/)e2e\/|(^|\/)fixtures?\/|(^|\/)scripts?\/|(^|\/)dist\/|(^|\/)build\/|(^|\/)node_modules\/|(^|\/)\.git\/|(^|\/)\.agents\/|\.d\.ts$)/;

// #16 guard-coverage (v1 of inter-procedural taint): what the PROJECT'S OWN sanitizer for a sink
// family looks like. A well-engineered project applies these widely (openclaw references an ssrf
// guard in 155 files); the bug is the sink site whose file doesn't reference one. Per-file heuristic
// — coarse (a guard reached via a cross-file wrapper is missed); full inter-procedural taint is #16.
const SANITIZER_SIGNALS: Partial<Record<AttackClass, RegExp>> = {
  // Node + C# guard names (union): a file referencing any of these is treated as guarding the class.
  ssrf: /\bssrf\b|ssrfPolicy|ssrfGuard|isPrivate(?:Host|Ip|Address)|blocked?Hosts?|denyHost|allow-?list|allowedHosts?|assertPublic|safeFetch|guardedFetch|validateUrl|isAllowedUrl|resolvePublicUrl|IsPrivateOrLoopback|HttpUrlRiskEvaluator|HttpUrlValidator|IsUrlSafe|DangerousUrlPattern|CanvasUrlSafety|BuildSafeHandler|hostAllowlist/i,
  "path-traversal": /isPathInside|sanitize(?:Path|Filename)|assertWithin|containsTraversal|resolveWithin|safeJoin|isSubPath|IsPathWithinRoot|GetFinalPathFromHandle|ResolveLinkTarget|writeExternalFileWithinRoot|GetFullPath|IsWithin/i,
  "missing-authentication": /Authenticat|Authoriz|VerifySignature|ValidateToken|\bbearer\b|apiKey|IsAuthenticated|CheckToken|requireAuth|\bhmac\b|McpAuthToken|BearerToken|signatureValid|ConstantTimeEquals|FixedTimeEquals/i,
  "broken-object-access": /OwnerId|ownedBy|IsOwner|belongsTo|\bprincipal\b|CheckOwnership|assertOwn|IsAuthorizedFor|scopedTo|AccessControl|RequireScope|EnsureApproved/i,
};

export interface SweepLead {
  file: string;
  line: number;
  lane: AttackClass;
  sink: string;
  /** Lane triage rank (SSRF sets it; `low` = fixed-host/path-only, rarely SSRF). See StaticLead. */
  priority?: "high" | "low";
  /** #16 guard-coverage: does this lead's FILE reference the project's OWN sanitizer for this sink
   *  family? `false` = the sink is here but the guard the project uses elsewhere is NOT referenced in
   *  this file — a guard-consistency gap, the sharpest reach-the-sink target. `undefined` = no guard
   *  signal is known for this lane. */
  guardCovered?: boolean;
}

export interface SweepReport {
  repo: string;
  filesScanned: number;
  leads: SweepLead[];
  /** Files with the most sink leads — where to point the LLM hunt / prove phase. */
  densityRanked: { file: string; leads: number }[];
  /** #16 v1: actionable leads whose file does NOT reference the project's own guard for that sink —
   *  where a project that guards this class elsewhere most likely missed a path. Full inter-procedural
   *  taint is the aspiration; this per-file signal is the tractable first cut. */
  guardGaps: SweepLead[];
}

/** Prefer `git ls-files` (respects .gitignore, fast); fall back to a bounded fs walk for a
 *  non-git clone. Paths returned are repo-relative and POSIX-ish. */
function listSourceFiles(repo: string): string[] {
  let files: string[];
  try {
    const out = execFileSync("git", ["-C", repo, "ls-files", ...SOURCE_EXTS.map((e) => `*.${e}`)], {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    });
    files = out.split("\n").map((s) => s.trim()).filter(Boolean);
  } catch {
    files = walk(repo, repo);
  }
  return [...new Set(files)].filter((f) => !SKIP_RE.test("/" + f));
}

function walk(dir: string, root: string, acc: string[] = []): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return acc;
  }
  for (const name of entries) {
    if (name === ".git" || name === "node_modules" || name === "dist" || name === "build") continue;
    const full = join(dir, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) walk(full, root, acc);
    else if (SOURCE_EXTS.some((e) => name.endsWith("." + e))) acc.push(relative(root, full));
  }
  return acc;
}

/** Scan `repo` for every lane's static sink leads and rank files by density. Pure + free. */
export function sweepRepo(repo: string, opts: { top?: number } = {}): SweepReport {
  const top = opts.top ?? 40;
  const files = listSourceFiles(repo);
  const leads: SweepLead[] = [];
  const perFile = new Map<string, number>();

  for (const rel of files) {
    let src: string;
    try {
      src = readFileSync(join(repo, rel), "utf8");
    } catch {
      continue;
    }
    // #16: which sink families does THIS file guard against (references the project's own sanitizer)?
    const guarded = new Set<AttackClass>();
    for (const lane of Object.keys(SANITIZER_SIGNALS) as AttackClass[]) {
      if (SANITIZER_SIGNALS[lane]!.test(src)) guarded.add(lane);
    }
    for (const attacker of ATTACKERS) {
      // Language-partition: a lane only scans files it handles (C# lanes → .cs, Node lanes → .ts/.js),
      // so a JS sink pattern never fires on a .cs file and vice versa.
      if (!attacker.handles(rel)) continue;
      const hasSignal = Boolean(SANITIZER_SIGNALS[attacker.attackClass]);
      for (const lead of attacker.staticLeads(src)) {
        leads.push({
          file: rel,
          line: lead.line,
          lane: attacker.attackClass,
          sink: lead.sink,
          priority: lead.priority,
          guardCovered: hasSignal ? guarded.has(attacker.attackClass) : undefined,
        });
        // Rank the density head by ACTIONABLE leads: a `low`-priority lead (fixed-host SSRF) doesn't
        // count toward where to point the expensive prove phase.
        if (lead.priority !== "low") perFile.set(rel, (perFile.get(rel) ?? 0) + 1);
      }
    }
  }

  const densityRanked = [...perFile.entries()]
    .map(([file, n]) => ({ file, leads: n }))
    .sort((a, b) => b.leads - a.leads)
    .slice(0, top);

  // #16 v1: the sharpest targets — actionable leads whose file doesn't reference the project's own
  // guard for that sink family (the class a well-engineered project ships: guarded everywhere but here).
  const guardGaps = leads.filter((l) => l.priority !== "low" && l.guardCovered === false);

  return { repo, filesScanned: files.length, leads, densityRanked, guardGaps };
}
