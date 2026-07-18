import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, NODE_RUN, NODE_SOURCE_RE, freshMarker, nodeExportedNames } from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// Resource exhaustion / ReDoS (CWE-400 / CWE-1333): untrusted input reaches a regex whose structure
// backtracks catastrophically (a nested-quantifier group `(a+)+`, a quantified overlapping alternation
// `(a|ab)+`, `(.*)*`). A short, benign-looking input then costs exponential/polynomial time and hangs
// the process — a one-request denial of service. Unlike the other lanes there is no "guard" to miss;
// the vuln is intrinsic to the regex. The find is a catastrophic-shaped regex reachable from an
// entrypoint; the proof is a FIRED hang — a crafted input that blows the time budget while a normal
// input returns instantly. (The hang differential is the observed proof, like the CSV lane's survival.)

// A catastrophic-backtracking group inside a regex body: a group that is quantified AND whose content is
// itself quantified or an alternation. `(a+)+`, `(\w+)*`, `(.+)+`, `(\d+)*`, `(a|ab)+`.
const CATASTROPHIC_SHAPE = /\((?:[^()]*[+*][^()]*|[^()|]*\|[^()]*)\)\s*[*+]/;

/** Every line carrying a regex literal (`/.../`) or `new RegExp("...")` whose pattern has a
 *  catastrophic-backtracking shape — the ReDoS lead surface. A regex-context gate avoids matching
 *  arithmetic like `(a + b) * c`. */
function catastrophicRegexLeads(source: string): StaticLead[] {
  const leads: StaticLead[] = [];
  const lines = source.split("\n");
  // regex literal bodies (handle escapes + char classes) and RegExp("…") string patterns
  const litRe = /\/((?:\\.|\[(?:\\.|[^\]\\])*\]|[^/\n\\])+)\/[gimsuy]*/g;
  const ctorRe = /\bRegExp\s*\(\s*(['"`])((?:\\.|(?!\1).)*)\1/g;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let hit = false;
    for (const m of line.matchAll(litRe)) if (CATASTROPHIC_SHAPE.test(m[1])) hit = true;
    for (const m of line.matchAll(ctorRe)) if (CATASTROPHIC_SHAPE.test(m[2])) hit = true;
    if (hit) leads.push({ line: i + 1, sink: "catastrophic-regex" });
  }
  return leads;
}

/**
 * Detect catastrophic backtracking by its TIME SIGNATURE, fast — no multi-second hang. Establish a
 * benign baseline (the function must be quick on normal input, else it is always-slow, not a ReDoS),
 * then feed SHORT evil inputs of increasing length across several char classes: a linear regex stays
 * sub-millisecond, a catastrophic one crosses the threshold within a few extra characters. Fired = a
 * short crafted input costs > THRESHOLD_MS while benign is fast. The ascending lengths mean detection
 * happens the instant the blowup crosses the line (usually < 1s), and the sandbox budget is the
 * backstop for an input that jumps straight past it.
 */
function redosDriver(moduleRel: string, fnName: string, marker: string): string {
  const mod = JSON.stringify("./" + moduleRel);
  const F = JSON.stringify(fnName);
  const MK = JSON.stringify(marker);
  return `
const MARKER = ${MK};
const THRESHOLD_MS = 400;
let m;
try { m = await import(${mod}); } catch (e) { process.stdout.write("IMPORT_FAIL:" + e); process.exit(0); }
function pick(n){ if (m && typeof m[n]==="function") return m[n]; if (m && m.default && typeof m.default[n]==="function") return m.default[n]; return null; }
const fn = pick(${F});
if (!fn) { process.stdout.write("NOT_A_FUNCTION"); process.exit(0); }
function shapes(v){ return [ [v], [{ input: v, text: v, value: v, query: v, name: v, pattern: v, content: v, url: v }], [v, v] ]; }
async function callAll(v){ for (const a of shapes(v)){ try { await fn(...a); } catch(e){} } }
// benign baseline — a normal input must be fast, else the function is always-slow (not an input-driven ReDoS)
const b0 = Date.now();
await callAll("a normal short value " + MARKER);
const benignMs = Date.now()-b0;
process.stdout.write("BENIGN_OK ms=" + benignMs + "\\n");
if (benignMs > 250){ process.stdout.write("SLOW_BASELINE — not input-driven\\n"); process.exit(0); }
// evil inputs: short single-class runs + a non-matching terminator, ascending length (fire the instant one crosses)
const classes = ["a", "1", " ", "\\t", "a1", "aA", "!a", "-"];
const terms = ["!", "@", "\\u0000", "X", " "];
for (let n = 20; n <= 42; n++){
  for (const c of classes){
    const evil = c.repeat(Math.ceil(n / c.length)) + terms[n % terms.length];
    process.stdout.write("TRY len=" + evil.length + "\\n");
    const s = Date.now();
    await callAll(evil);          // a catastrophic regex either crosses THRESHOLD here or never returns (sandbox kills it)
    const dt = Date.now()-s;
    if (dt > THRESHOLD_MS){ process.stdout.write("REDOS_FIRED len=" + evil.length + " ms=" + dt + "\\n"); process.exit(0); }
  }
}
process.stdout.write("COMPLETED no-redos\\n");
`.trim();
}

export class ResourceExhaustionAttacker implements Attacker {
  readonly attackClass = "resource-exhaustion" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "resource-exhaustion-node");
  private static readonly BUDGET_MS = 2500;

  handles(file: string): boolean {
    return NODE_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    return catastrophicRegexLeads(source);
  }

  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
    const exploits: Exploit[] = [];
    for (const file of files) {
      if (!this.handles(file)) continue;
      let source: string;
      try {
        source = readFileSync(join(targetDir, file), "utf8");
      } catch {
        continue;
      }
      const leads = catastrophicRegexLeads(source);
      if (leads.length === 0) continue; // no catastrophic-shaped regex → nothing to blow up
      const names = nodeExportedNames(source);
      if (names.length === 0) continue;

      let fired = false;
      for (const name of names) {
        if (fired) break;
        const marker = freshMarker();
        const driverRel = `.raeuber-redos-${marker}.mjs`;
        sandbox.writeFile(driverRel, redosDriver(file, name, marker));
        const run = sandbox.exec(`${NODE_RUN} ${driverRel} 2>&1`, ResourceExhaustionAttacker.BUDGET_MS);
        const out = run.stdout + run.stderr;
        const benignRan = out.includes("BENIGN_OK") && !out.includes("SLOW_BASELINE");
        const measured = out.includes("REDOS_FIRED");
        // Exponential jump: benign printed, we entered a TRY, but the driver never COMPLETED and was killed.
        const hung = run.timedOut && benignRan && out.includes("TRY len=") && !out.includes("COMPLETED");
        if (!measured && !hung) continue;
        const lastTry = [...out.matchAll(/TRY len=(\d+)/g)].pop();
        exploits.push({
          attackClass: "resource-exhaustion",
          proof: "input-caused-hang",
          file,
          line: leads[0].line,
          sink: "catastrophic-regex",
          summary:
            `Exported \`${name}()\` applies a catastrophic-backtracking regex to its input; a short crafted input (${lastTry ? `${lastTry[1]} chars` : "a single-class run + a non-matching terminator"}) drove ${measured ? "super-linear time past the threshold" : "the process into a hang (killed at the sandbox budget)"} while a benign input returned instantly — a single-request ReDoS (CWE-1333/CWE-400).`,
          payload: `${name}("aaa…aaa!")  // long run of one class char + a non-matching terminator`,
          evidence:
            `benign input returned fast; the crafted input ${measured ? "measured over the 1.5s threshold" : "hung the process past the 6s sandbox budget"}:\n` +
            out.slice(0, 700),
        });
        fired = true;
      }
    }
    return exploits;
  }
}
