import { randomBytes } from "node:crypto";
import type { AttackClass, Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";

/**
 * An attacker lane. Each lane knows one vulnerability class, ships a planted-vulnerable fixture its
 * canary must successfully exploit (proving the lane is LIVE — the family's "the detector caught its
 * own planted defect or it's quarantined" rule), and can `hunt` a target for that class.
 *
 * `hunt` runs INSIDE an already-open sandbox over `targetDir`: it detects candidate sinks statically
 * (a free lead), then DRIVES adversarial payloads through the reachable entrypoints and keeps only
 * the ones that fire — a returned Exploit always carries observed evidence.
 */
/** A static sink lead: a source line whose shape matches a lane's sink pattern. A lead is NOT a
 *  finding — it is the FREE pre-filter that tells the hunt where to point the (expensive) prove
 *  phase. Only an executed PoC is a finding. */
export interface StaticLead {
  line: number;
  sink: string;
}

export interface Attacker {
  readonly attackClass: AttackClass;
  /** True if this lane can attack the given changed file (by language/extension). */
  handles(file: string): boolean;
  /** Absolute path to the planted-vulnerable fixture dir the canary attacks to prove liveness. */
  readonly canaryFixtureDir: string;
  /** Find and PROVE exploits of this class among `files`, using `sandbox` to execute PoCs. */
  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[];
  /** Every source line matching this lane's sink pattern — the hunt sweep's free pre-filter. The
   *  gate and the hunt agree on "what a sink is" because both flow through this lane's SINK_RE. */
  staticLeads(source: string): StaticLead[];
}

/** Collect every line whose text matches `re`, tagging the sink token (callee before `(`). Shared
 *  by the lanes so the hunt sweep detects exactly the sinks the gate would drive. */
export function scanSinkLeads(source: string, re: RegExp): StaticLead[] {
  const leads: StaticLead[] = [];
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(re);
    if (m) leads.push({ line: i + 1, sink: m[0].split("(")[0].trim() });
  }
  return leads;
}

/**
 * A per-run, unguessable marker. A payload injects `echo <marker>` (or reads a decoy whose content
 * is `<marker>`); observing `<marker>` back in the sandbox output is proof the sink executed — it
 * cannot occur by coincidence, and a fixed string could be spoofed by unrelated code, so it must be
 * random per run.
 */
export function freshMarker(): string {
  return "RAEUBER_" + randomBytes(9).toString("hex");
}

/**
 * A CommonJS driver that requires `moduleRel` and calls `fnName(arg)` — the first parameter, the
 * canonical injectable position — then prints anything the call returns or an error carries, so
 * output produced by the exercised sink (an echoed marker, a traversed file's contents) is
 * observable. Shared by the Node lanes. CommonJS require runs without a build step (Chunk 0 targets
 * .js/.cjs; .mjs/.ts transpile is a later refinement).
 */
export function nodeRequireDriver(moduleRel: string, fnName: string, arg: string): string {
  const a = JSON.stringify(arg);
  const mod = JSON.stringify("./" + moduleRel);
  const fn = JSON.stringify(fnName);
  return `
(async () => {
  let m; try { m = require(${mod}); } catch (e) { process.stdout.write("REQUIRE_FAIL:" + e); return; }
  const fn = (m && m[${fn}]) || (m && m.default && m.default[${fn}]) || (m && m.default);
  if (typeof fn !== "function") { process.stdout.write("NOT_A_FUNCTION"); return; }
  try {
    const r = await fn(${a});
    process.stdout.write(String(r && r.stdout ? r.stdout : (r == null ? "" : r)));
  } catch (e) {
    process.stdout.write(String((e && e.stdout) || (e && e.message) || e || ""));
  }
})();
`.trim();
}

/** Exported symbol names in Node source we can try to drive. */
export function nodeExportedNames(source: string): string[] {
  const re =
    /export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=|export\s+const\s+([A-Za-z_$][\w$]*)\s*=/g;
  const names = new Set<string>();
  for (const m of source.matchAll(re)) {
    const name = m[1] || m[2] || m[3];
    if (name) names.add(name);
  }
  return [...names];
}
