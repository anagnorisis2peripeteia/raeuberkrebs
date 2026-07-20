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
// input returns instantly — a single-request ReDoS (CWE-1333/CWE-400).

// A catastrophic-backtracking group inside a regex body: a group that is quantified AND whose content is
// itself quantified or an alternation. `(a+)+`, `(\w+)*`, `(.+)+`, `(\d+)*`, `(a|ab)+`.
const CATASTROPHIC_SHAPE = /\((?:[^()]*[+*][^()]*|[^()|]*\|[^()]*)\)\s*[*+]/;

// Minimal deep-JSON stress surface: parse untrusted strings without obvious depth/size guards.
const DEEP_JSON_RE = /\bJSON\.parse\s*\(/;

/** Every line carrying a regex literal (`/.../`) or `new RegExp("...")` whose pattern has a
 * catastrophic-backtracking shape — the ReDoS lead surface. A regex-context gate avoids matching
 * arithmetic like `(a + b) * c`. */
function catastrophicRegexLeads(source: string): StaticLead[] {
  const leads: StaticLead[] = [];
  const lines = source.split("\n");
  // regex literal bodies (handle escapes + char classes) and RegExp("…") string patterns
  const litRe = /\/((?:\\.|\[(?:\\.|[^]\\])*\]|[^/\n\\])+?)\/[gimsuy]*/g;
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

function deepJsonLeads(source: string): StaticLead[] {
  const leads: StaticLead[] = [];
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (DEEP_JSON_RE.test(lines[i])) leads.push({ line: i + 1, sink: "deep-json" });
  }
  return leads;
}

/**
 * Detect catastrophic backtracking by its TIME SIGNATURE, fast — no multi-second hang. Establish a
 * benign baseline (the function must be quick on normal input, else it is always-slow, not a ReDoS),
 * then feed SHORT evil inputs of increasing length across several char classes: a linear regex stays
 * predictable, a catastrophic one crosses the threshold within a few extra characters. Fired = a short
 * crafted input consistently exceeds a stable baseline by a margin and budget, while benign inputs stay
 * fast. To reduce timing noise, every candidate is measured 3 times and a median is used for both
 * baseline and candidate.
 */
function redosDriver(moduleRel: string, fnName: string, marker: string): string {
  const mod = JSON.stringify("./" + moduleRel);
  const F = JSON.stringify(fnName);
  const MK = JSON.stringify(marker);
  return `
const SAMPLE_COUNT = 4;
const MARKER = ${MK};
const ABS_THRESHOLD_MS = 400;
const BASELINE_THRESHOLD_MS = 250;
const BASELINE_FACTOR = 6;
const SLOPE_MARGIN_MS = 250;
let m;
try { m = await import(${mod}); } catch (e) { process.stdout.write("IMPORT_FAIL:" + e); process.exit(0); }
function pick(n){ if (m && typeof m[n]==="function") return m[n]; if (m && m.default && typeof m.default[n]==="function") return m.default[n]; return null; }
const fn = pick(${F});
if (!fn) { process.stdout.write("NOT_A_FUNCTION"); process.exit(0); }
function shapes(v){ return [ [v], [{ input: v, text: v, value: v, query: v, name: v, pattern: v, content: v, url: v }], [v, v] ]; }
async function callAll(v){ for (const a of shapes(v)){ try { await fn(...a); } catch(e){} } }
async function sample(v){
  const samples = [];
  for (let i = 0; i < SAMPLE_COUNT; i++) {
    const s = Date.now();
    await callAll(v);
    samples.push(Date.now()-s);
  }
  samples.sort((a,b)=>a-b);
  return samples[Math.floor(samples.length / 2)];
}
function hitThreshold(base, sample) {
  const ratio = Math.max(sample / Math.max(base, 1), 1);
  return (
    sample > ABS_THRESHOLD_MS &&
    (ratio >= BASELINE_FACTOR || sample >= base + SLOPE_MARGIN_MS)
  );
}

// benign baseline — 3 short values; a function that's always-slow isn't input-driven ReDoS.
const benignSamples = [
  await sample("a normal short value " + MARKER),
  await sample("prefix_" + MARKER + "_ok"),
  await sample("literal-text-without-control"),
];
const benignMs = Math.max(...benignSamples);
process.stdout.write("BENIGN_OK samples=" + benignSamples.join(",") + "\\n");
if (benignMs > BASELINE_THRESHOLD_MS * 2){ process.stdout.write("SLOW_BASELINE — not input-driven\\n"); process.exit(0); }
// evil inputs: short single-class runs + a non-matching terminator, ascending length (fire the instant one crosses)
const classes = ["a", "1", " ", "\\t", "a1", "aA", "!a", "-"];
const terms = ["!", "@", "\\u0000", "X", " "];
for (let n = 20; n <= 42; n++){
  for (const c of classes){
    const evil = c.repeat(Math.ceil(n / c.length)) + terms[n % terms.length];
    process.stdout.write("TRY len=" + evil.length + "\\n");
    const dt = await sample(evil); // a catastrophic regex either crosses threshold here or never returns (sandbox kills it)
    if (hitThreshold(benignMs, dt)) { process.stdout.write("REDOS_FIRED len=" + evil.length + " ms=" + dt + " baseline=" + benignMs + "\\n"); process.exit(0); }
  }
}
process.stdout.write("COMPLETED no-redos\\n");
`.trim();
}

/**
 * Detect deep-JSON parse stress: `JSON.parse` against attacker-shaped input can become O(size) or
 * overflow recursion/stack on unbounded payload depth. This driver uses increasingly deep nesting and
 * measures input-driven latency against a benign baseline. A deep payload that crosses THRESHOLD_MS or
 * hangs within budget indicates potential resource exhaustion.
 */
function deepJsonDriver(moduleRel: string, fnName: string, marker: string): string {
  const mod = JSON.stringify("./" + moduleRel);
  const F = JSON.stringify(fnName);
  const MK = JSON.stringify(marker);
  return `
const MARKER = ${MK};
const THRESHOLD_MS = 400;
const DEPTHS = [120, 240, 480, 960, 1920];
let m;
try { m = await import(${mod}); } catch (e) { process.stdout.write("IMPORT_FAIL:" + e); process.exit(0); }
function pick(n){ if (m && typeof m[n]==="function") return m[n]; if (m && m.default && typeof m.default[n]==="function") return m.default[n]; return null; }
const fn = pick(${F});
if (!fn) { process.stdout.write("NOT_A_FUNCTION"); process.exit(0); }

function deepArray(level){
  let payload = '"a"';
  for (let i = 0; i < level; i++) payload = "[" + payload + "]";
  return payload;
}
function shapes(v){ return [v, { input: v, body: v, payload: v, data: v, value: v, json: v }, [v, v], [v, "marker=" + MARKER] ]; }

async function callWithTiming(v){
  const start = Date.now();
  for (const a of shapes(v)) {
    try { await fn(...a); } catch (e) {}
    const dt = Date.now() - start;
    if (dt > THRESHOLD_MS) throw new Error("DEEP_JSON_STRESS" + dt);
  }
}

const b0 = Date.now();
await callWithTiming("normal value " + MARKER);
const benignMs = Date.now()-b0;
process.stdout.write("BENIGN_OK ms=" + benignMs + "\\n");
if (benignMs > 250){ process.stdout.write("SLOW_BASELINE — not input-driven\\n"); process.exit(0); }

for (const depth of DEPTHS){
  const payload = deepArray(depth);
  process.stdout.write("TRY depth=" + depth + " len=" + payload.length + "\\n");
  try {
    await callWithTiming(payload);
  } catch (e) {
    if (String(e).includes("DEEP_JSON_STRESS")) {
      process.stdout.write("DEEP_JSON_FIRED depth=" + depth + "\\n");
      process.exit(0);
    }
  }
}
process.stdout.write("COMPLETED no-deep-json\\n");
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
    return [...catastrophicRegexLeads(source), ...deepJsonLeads(source)];
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

      const regexLeads = catastrophicRegexLeads(source);
      const jsonLeads = deepJsonLeads(source);
      if (regexLeads.length === 0 && jsonLeads.length === 0) continue;

      const names = nodeExportedNames(source);
      if (names.length === 0) continue;

      let fired = false;
      for (const name of names) {
        if (fired) break;

        if (regexLeads.length > 0) {
          const marker = freshMarker();
          const driverRel = `.raeuber-redos-${marker}.mjs`;
          sandbox.writeFile(driverRel, redosDriver(file, name, marker));
          const run = sandbox.exec(`${NODE_RUN} ${driverRel} 2>&1`, ResourceExhaustionAttacker.BUDGET_MS);
          const out = run.stdout + run.stderr;
          const benignRan = out.includes("BENIGN_OK") && !out.includes("SLOW_BASELINE");
          const measured = out.includes("REDOS_FIRED");
          // Exponential jump: benign printed, we entered a TRY, but the driver never COMPLETED and was killed.
          const hung = run.timedOut && benignRan && out.includes("TRY len=") && !out.includes("COMPLETED");
          if (measured || hung) {
            const lastTry = [...out.matchAll(/TRY len=(\d+)/g)].pop();
            exploits.push({
              attackClass: "resource-exhaustion",
              proof: "input-caused-hang",
              file,
              line: regexLeads[0].line,
              sink: "catastrophic-regex",
              summary:
                `Exported \`${name}()\` applies a catastrophic-backtracking regex to its input; a short crafted input (${lastTry ? `${lastTry[1]} chars` : "a single-class run + a non-matching terminator"}) drove ${measured ? "super-linear time past the threshold" : "the process into a hang (killed at the sandbox budget)"} while a benign input returned instantly — a single-request ReDoS (CWE-1333/CWE-400).`,
              payload: `${name}("aaa...aaa!")  // long run of one class char + a non-matching terminator`,
              evidence:
                `benign input returned fast; the crafted input ${measured ? "measured over the 1.5s threshold" : "hung the process past the sandbox budget"}:\n` +
                out.slice(0, 700),
            });
            fired = true;
            continue;
          }
        }

        if (jsonLeads.length === 0 || fired) continue;
        const jsonMarker = freshMarker();
        const jsonDriverRel = `.raeuber-deep-json-${jsonMarker}.mjs`;
        sandbox.writeFile(jsonDriverRel, deepJsonDriver(file, name, jsonMarker));
        const runJson = sandbox.exec(`${NODE_RUN} ${jsonDriverRel} 2>&1`, ResourceExhaustionAttacker.BUDGET_MS);
        const outJson = runJson.stdout + runJson.stderr;
        const benignJson = outJson.includes("BENIGN_OK") && !outJson.includes("SLOW_BASELINE");
        const measuredJson = outJson.includes("DEEP_JSON_FIRED");
        const hungJson = runJson.timedOut && benignJson && outJson.includes("TRY depth=") && !outJson.includes("COMPLETED");
        if (!measuredJson && !hungJson) continue;

        const lastTryJson = [...outJson.matchAll(/TRY depth=(\d+)/g)].pop();
        exploits.push({
          attackClass: "resource-exhaustion",
          proof: "input-caused-hang",
          file,
          line: jsonLeads[0].line,
          sink: "deep-json",
          summary:
            `Exported \`${name}()\` appears to process deep JSON input directly via parsing paths; nested input (${lastTryJson ? `${lastTryJson[1]} levels` : "deep nesting"}) exceeded the threshold or hung while a benign input remained fast — a single-request resource-exhaustion risk (CWE-400).`,
          payload: `${name}("[ ... nested JSON arrays ... ]")`,
          evidence:
            `benign input returned fast; crafted deep input ${measuredJson ? "crossed the 1.5s threshold" : "hit the sandbox budget"}:\n` +
            outJson.slice(0, 700),
        });
        fired = true;
      }
    }
    return exploits;
  }
}
