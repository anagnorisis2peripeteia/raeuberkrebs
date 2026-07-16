import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, freshMarker } from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// A command-injection sink in Node: a child_process call whose command string is built from a
// variable (interpolation or concatenation) rather than a fixed literal — the classic
// `exec('ping ' + host)` shape. This is only a LEAD; the finding is a payload that fires.
const SINK_RE =
  /\b(?:execSync|exec|execFileSync|execFile|spawnSync|spawn)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+|[A-Za-z_$][\w$]*\s*\+)/;

// Exported symbol names we can try to drive: `export function f`, `export const f =`,
// `exports.f =` / `module.exports.f =` (any RHS — the driver checks it's callable). First non-empty
// group is the name. (Object-shorthand `module.exports = { f }` is a Chunk 1 refinement.)
const EXPORT_RE =
  /export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=|export\s+const\s+([A-Za-z_$][\w$]*)\s*=/g;

// Benign proof-of-execution payloads: each injects `echo <marker>` via a different shell
// metacharacter. Firing means the injected echo ran — the vuln is proven, nothing is harmed.
function payloads(marker: string): string[] {
  return [
    `x; echo ${marker}`,
    `x$(echo ${marker})`,
    `x\`echo ${marker}\``,
    `x | echo ${marker}`,
    `x && echo ${marker}`,
  ];
}

function exportedNames(source: string): string[] {
  const names = new Set<string>();
  for (const m of source.matchAll(EXPORT_RE)) {
    const name = m[1] || m[2] || m[3];
    if (name) names.add(name);
  }
  return [...names];
}

/** Line number (1-indexed) of the first sink, for the evidence trail. */
function firstSinkLine(source: string): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) if (SINK_RE.test(lines[i])) return i + 1;
  return 1;
}

/**
 * A driver that requires `moduleRel` and calls `fnName(payload)` — the first parameter, the
 * canonical injectable position. Prints anything the call returns / an exec error carries, so a
 * marker echoed by the injected child process is observable. CommonJS require runs without a build
 * step (Chunk 0 targets .js/.cjs; .mjs/.ts transpile is a Chunk 1 refinement).
 */
function driver(moduleRel: string, fnName: string, payload: string): string {
  const p = JSON.stringify(payload);
  const mod = JSON.stringify("./" + moduleRel);
  const fn = JSON.stringify(fnName);
  return `
(async () => {
  let m; try { m = require(${mod}); } catch (e) { process.stdout.write("REQUIRE_FAIL:" + e); return; }
  const fn = (m && m[${fn}]) || (m && m.default && m.default[${fn}]) || (m && m.default);
  if (typeof fn !== "function") { process.stdout.write("NOT_A_FUNCTION"); return; }
  try {
    const r = await fn(${p});
    process.stdout.write(String(r && r.stdout ? r.stdout : (r == null ? "" : r)));
  } catch (e) {
    process.stdout.write(String((e && e.stdout) || (e && e.message) || e || ""));
  }
})();
`.trim();
}

export class CommandInjectionAttacker implements Attacker {
  readonly attackClass = "command-injection" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "command-injection-node");

  handles(file: string): boolean {
    return /\.(?:js|cjs)$/.test(file);
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
      if (!SINK_RE.test(source)) continue; // no sink lead — nothing to drive
      const names = exportedNames(source);
      if (names.length === 0) continue; // reachable sink but no exported entrypoint to drive
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "child_process").split("(")[0].trim();

      let fired = false;
      for (const name of names) {
        if (fired) break;
        const marker = freshMarker();
        for (const payload of payloads(marker)) {
          const driverRel = `.raeuber-driver-${marker}.cjs`;
          sandbox.writeFile(driverRel, driver(file, name, payload));
          const run = sandbox.exec(`node ${driverRel} 2>&1`, 15_000);
          const out = run.stdout + run.stderr;
          // Fired = the marker appears in output SOMEWHERE OTHER than inside the literal
          // `echo <marker>` we injected. If the app merely echoed our payload back verbatim, the
          // only occurrence is that literal (stripped here) and this is false — no false positive.
          // If the injection executed, the child's bare `<marker>` (or a substituted `x<marker>`)
          // survives the strip.
          const executed = out.replace(new RegExp(`echo\\s+${marker}`, "g"), "").includes(marker);
          if (executed) {
            exploits.push({
              attackClass: "command-injection",
              proof: "marker-executed",
              file,
              line: sinkLine,
              sink,
              summary: `Untrusted first argument of exported \`${name}()\` reaches a shell sink; an injected echo executed.`,
              payload,
              evidence:
                `driver called ${name}(${JSON.stringify(payload)}); the injected marker ${marker} ` +
                `appeared in child-process output:\n` +
                out.slice(0, 800),
            });
            fired = true;
            break;
          }
        }
      }
    }
    return exploits;
  }
}
