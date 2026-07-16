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

const SOURCE_EXTS = ["ts", "mts", "cts", "js", "cjs", "mjs"];
// Exclude tests/fixtures/build output/vendored code — same spirit as the gate's scope.
const SKIP_RE =
  /(\.test\.|\.spec\.|(^|\/)tests?\/|(^|\/)__tests__\/|(^|\/)fixtures?\/|(^|\/)dist\/|(^|\/)build\/|(^|\/)node_modules\/|(^|\/)\.git\/|\.d\.ts$)/;

export interface SweepLead {
  file: string;
  line: number;
  lane: AttackClass;
  sink: string;
  /** Lane triage rank (SSRF sets it; `low` = fixed-host/path-only, rarely SSRF). See StaticLead. */
  priority?: "high" | "low";
}

export interface SweepReport {
  repo: string;
  filesScanned: number;
  leads: SweepLead[];
  /** Files with the most sink leads — where to point the LLM hunt / prove phase. */
  densityRanked: { file: string; leads: number }[];
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
    for (const attacker of ATTACKERS) {
      for (const lead of attacker.staticLeads(src)) {
        leads.push({ file: rel, line: lead.line, lane: attacker.attackClass, sink: lead.sink, priority: lead.priority });
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

  return { repo, filesScanned: files.length, leads, densityRanked };
}
