import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Exploit, ExploitProof } from "../types.js";
import { type Sandbox, ensurePythonEnv } from "../sandbox.js";
import { type StaticLead, PYTHON_SOURCE_RE, freshMarker } from "./attacker.js";
import { type CoverageDiffItem, coverageDifferentialDriver, shq } from "./python-driver.js";

// Shared machinery for the command-guard differential lanes (the carrier-corpus / coverage-gap
// family). Every such lane probes a target's own command-safety DETECTOR — an `is_dangerous` /
// `detect_dangerous_command` / `is_blocked` classifier — and proves the detector's denylist is
// incomplete for a danger category: it flags a gated CONTROL sibling but clears an equivalent-intent
// CARRIER. The discovery + hunt loop are identical across categories, so they live here; a concrete
// lane supplies only its curated corpus and the danger-family label.

// A danger-DETECTOR is a `def name(arg, …)` whose name marks it as a danger/blocklist classifier. The
// executor exclusion keeps us from ever *passing* a dangerous seed to a run/exec function — the seeds
// are only ever handed to a pure classifier, never to something that would run them.
const DEF_RE = /^def\s+([A-Za-z_]\w*)\s*\(\s*[A-Za-z_*]/gm;
const DETECTOR_RE =
  /(?:dangerous|danger|blocked|blocklist|denylist|denied|forbidden|malicious|unsafe|harmful|destructive|hardline|injection|suspicious|risky|threat|is_bad|disallow|prohibited)/i;
const EXECUTOR_RE = /(?:\brun\b|exec|spawn|system|popen|\bcall\b|invoke|dispatch|shell_?out)/i;

/** Names of the danger-classifier functions in `source` (a danger-ish name, not an executor). */
export function detectorFunctions(source: string): string[] {
  const names: string[] = [];
  for (const m of source.matchAll(DEF_RE)) {
    const name = m[1];
    if (DETECTOR_RE.test(name) && !EXECUTOR_RE.test(name)) names.push(name);
  }
  return [...new Set(names)];
}

/** The 1-based line of the first detector in `names`, for the exploit/lead anchor. */
export function firstDetectorLine(source: string, names: Set<string>): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^def\s+([A-Za-z_]\w*)\s*\(/);
    if (m && names.has(m[1])) return i + 1;
  }
  return 1;
}

/** Static leads: every danger-detector definition line (the free pre-filter for the coverage sweep). */
export function detectorLeads(source: string): StaticLead[] {
  const names = detectorFunctions(source);
  if (names.length === 0) return [];
  const lines = source.split("\n");
  const leads: StaticLead[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^def\s+([A-Za-z_]\w*)\s*\(/);
    if (m && names.includes(m[1] ?? "")) leads.push({ line: i + 1, sink: `detector:${m[1]}()` });
  }
  return leads;
}

export interface CoverageDifferentialSpec {
  /** Curated (control, carrier) pairs of a single danger category. */
  corpus: CoverageDiffItem[];
  /** Human label for the danger family, used in the exploit summary (e.g. "reverse-shell / C2 egress"). */
  family: string;
  /** Exploit proof label — defaults to `coverage-gap`. */
  proof?: ExploitProof;
}

/**
 * The shared coverage-differential hunt: for each changed Python file that defines a danger-detector,
 * drive the detector with the spec's corpus and record one exploit per (control, carrier) pair the
 * guard flags-then-clears. Neither command is executed — the detector is called only as a pure string
 * classifier, and the divergence between two same-category commands is the evidence.
 */
export function coverageDifferentialHunt(
  targetDir: string,
  files: string[],
  sandbox: Sandbox,
  spec: CoverageDifferentialSpec,
): Exploit[] {
  const exploits: Exploit[] = [];
  const proof = spec.proof ?? "coverage-gap";
  const py = ensurePythonEnv(sandbox, targetDir);
  const seen = new Set<string>();
  for (const file of files) {
    if (!PYTHON_SOURCE_RE.test(file)) continue;
    let source: string;
    try {
      source = readFileSync(join(targetDir, file), "utf8");
    } catch {
      continue;
    }
    const names = detectorFunctions(source);
    if (names.length === 0) continue;
    const detectorLine = firstDetectorLine(source, new Set(names));

    const marker = freshMarker();
    const driverRel = `.raeuber-coverage-${marker}.py`;
    sandbox.writeFile(driverRel, coverageDifferentialDriver(file, names, spec.corpus));
    const out = sandbox.exec(`${py} ${shq(driverRel)} 2>&1`, 30_000);
    const output = out.stdout + out.stderr;
    for (const line of output.split("\n")) {
      const m = line.match(/^RK_COVERAGE fn=(\S+) (.+)$/);
      if (!m) continue;
      const fnName = m[1];
      let item: CoverageDiffItem;
      try {
        item = JSON.parse(m[2] ?? "");
      } catch {
        continue;
      }
      const key = `${file}::${fnName}::${item.carrier}`;
      if (seen.has(key)) continue;
      seen.add(key);
      exploits.push({
        attackClass: "policy-belief-divergence",
        proof,
        file,
        line: detectorLine,
        sink: `detector:${fnName}()`,
        summary:
          `The danger detector \`${fnName}()\` flags the ${spec.family} command \`${item.control}\` but ` +
          `CLEARS the equivalent ${item.category} carrier \`${item.carrier}\` (${item.technique}) — the ` +
          `same effect via a spelling its denylist misses, so the carrier bypasses the guard (fail-open).`,
        payload: item.carrier,
        evidence:
          `${fnName}(${JSON.stringify(item.control)}) = flagged, ` +
          `${fnName}(${JSON.stringify(item.carrier)}) = cleared; both are ${item.category} ` +
          `(${item.technique}), so the guard's coverage of this category is incomplete:\n` +
          output.slice(0, 400),
      });
    }
  }
  return exploits;
}
