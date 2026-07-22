import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import { type Sandbox, bundleForImport } from "../sandbox.js";
import { type Attacker, type StaticLead, nodeRunCommand, NODE_SOURCE_RE, freshMarker, nodeExportedNames, nodeImportDriver, scanSinkLeads } from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// A command-injection sink in Node: a child_process call whose command string is built from a
// variable (interpolation or concatenation) rather than a fixed literal — the classic
// `exec('ping ' + host)` shape. This is only a LEAD; the finding is a payload that fires.
const SINK_RE =
  /\b(?:execSync|exec|execFileSync|execFile|spawnSync|spawn)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+|[A-Za-z_$][\w$]*\s*\+)/;

// The bare `exec` alternative in SINK_RE also matches `db.exec(...)` (SQLite), `stmt.exec()`, and
// `regex.exec()` — none of which are a shell. A command-injection sink is child_process, so require
// the file to actually pull in child_process; a file that only does SQLite/regex `.exec()` never
// imports it, so its leads drop out (issue #10). A false-positive `.exec()` couldn't fire the shell
// marker anyway, but this keeps it out of the lead list and the density ranking.
const CHILD_PROCESS_RE =
  /(?:require\(\s*['"](?:node:)?child_process['"]|from\s+['"](?:node:)?child_process['"]|import\s+['"](?:node:)?child_process['"])/;

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

/** Line number (1-indexed) of the first sink, for the evidence trail. */
function firstSinkLine(source: string): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) if (SINK_RE.test(lines[i])) return i + 1;
  return 1;
}

export class CommandInjectionAttacker implements Attacker {
  readonly attackClass = "command-injection" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "command-injection-node");

  handles(file: string): boolean {
    return NODE_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    if (!CHILD_PROCESS_RE.test(source)) return []; // not a child_process file → the `.exec(` is not a shell
    return scanSinkLeads(source, SINK_RE);
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
      if (!CHILD_PROCESS_RE.test(source)) continue; // not a child_process file — the `.exec(` is not a shell
      if (!SINK_RE.test(source)) continue; // no sink lead — nothing to drive
      const names = nodeExportedNames(source);
      if (names.length === 0) continue; // reachable sink but no exported entrypoint to drive
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "child_process").split("(")[0].trim();

      // Bundle the module so it's importable even in build-toolchain repos (workspace
      // deps, ESM/CJS, path aliases); fall back to the raw file when bundling isn't needed.
      const importRel = bundleForImport(sandbox, file) ?? file;
      let fired = false;
      for (const name of names) {
        if (fired) break;
        const marker = freshMarker();
        for (const payload of payloads(marker)) {
          const driverRel = `.raeuber-driver-${marker}.mjs`;
          sandbox.writeFile(driverRel, nodeImportDriver(importRel, name, payload));
          const run = sandbox.exec(`${nodeRunCommand(targetDir)} ${driverRel} 2>&1`, 15_000);
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
