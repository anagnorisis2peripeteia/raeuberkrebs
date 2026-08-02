import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import { type Sandbox, bundleForImport } from "../sandbox.js";
import { type Attacker, type StaticLead, nodeRunCommand, NODE_SOURCE_RE, freshMarker, nodeExportedNames, scanSinkLeads } from "./attacker.js";
import { driveEntrypointDriver } from "./entrypoint-driver.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// A command-injection sink in Node: a child_process call whose command string is built from a
// variable (interpolation or concatenation) rather than a fixed literal — the classic
// `exec('ping ' + host)` shape. This is only a LEAD; the finding is a payload that fires.
// A child_process call whose command argument is NOT a plain string literal: a template with an
// interpolation, a `"str" + …` concatenation, OR a bare variable / call expression (`exec(cmd)`,
// `exec(buildCmd(x))`) — real code usually builds the command string upstream and passes the variable,
// so requiring the concatenation AT the call site (the old regex) missed most real sinks. A fixed
// literal (`exec("ls")`) still doesn't match. Over-matching is safe: the drive is the oracle — a
// non-tainted variable simply never fires the injected marker.
const SINK_RE =
  /\b(?:execSync|exec|execFileSync|execFile|spawnSync|spawn)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+|[A-Za-z_$][\w$]*)/;

// The bare `exec` alternative in SINK_RE also matches `db.exec(...)` (SQLite), `stmt.exec()`, and
// `regex.exec()` — none of which are a shell. A command-injection sink is child_process, so require
// the file to actually pull in child_process; a file that only does SQLite/regex `.exec()` never
// imports it, so its leads drop out (issue #10). A false-positive `.exec()` couldn't fire the shell
// marker anyway, but this keeps it out of the lead list and the density ranking.
const CHILD_PROCESS_RE =
  /(?:require\(\s*['"](?:node:)?child_process['"]|from\s+['"](?:node:)?child_process['"]|import\s+['"](?:node:)?child_process['"])/;

// Benign proof-of-execution payloads: each injects, via a different shell metacharacter, a command
// that WRITES a marker file. Firing = a shell reached through the entrypoint ran the injected write,
// so the marker file appears — observable whether the sink is synchronous or fires later in an async
// callback/promise. A function that merely returns/stores the payload string never creates the file
// (it's a specific random path only the injected `echo … > file` writes), so there is no false
// positive on safe code, including non-shell `execFile`/`spawn` with array args.
function payloads(marker: string, mf: string): string[] {
  return [
    `x; echo ${marker} > ${mf}`,
    `x$(echo ${marker} > ${mf})`,
    `x\`echo ${marker} > ${mf}\``,
    `x | echo ${marker} > ${mf}`,
    `x && echo ${marker} > ${mf}`,
    `x' ; echo ${marker} > ${mf} ; '`,
    `x" ; echo ${marker} > ${mf} ; "`,
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
      // Drive a synthetic "default" when there are no named exports — many real command-exec libs are a
      // bare `module.exports = function` (e.g. local-devices, growl); the shared driver resolves the
      // default/module-as-function from `m` regardless of the name.
      const names = nodeExportedNames(source);
      const driveNames = names.length > 0 ? names : ["default"];
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "child_process").split("(")[0].trim();

      // Bundle the module so it's importable even in build-toolchain repos (workspace
      // deps, ESM/CJS, path aliases); fall back to the raw file when bundling isn't needed.
      const importRel = bundleForImport(sandbox, file) ?? file;
      let fired = false;
      for (const name of driveNames) {
        if (fired) break;
        const marker = freshMarker();
        const mf = `.rk-cmdi-${marker}`;
        const driverRel = `.raeuber-driver-${marker}.mjs`;
        // The upgraded driver enumerates real entrypoint shapes (function, class-constructor+method),
        // injection positions (positional + config-object fields), supplies a callback, and settles so
        // an async sink lands — then we observe the marker FILE the payload writes.
        sandbox.writeFile(driverRel, driveEntrypointDriver(importRel, name, payloads(marker, mf)));
        sandbox.exec(`${nodeRunCommand(targetDir)} ${driverRel} 2>&1`, 25_000);
        // Host-side, crash-robust: read + clear the marker file. Its presence with the marker means a
        // shell reached through `name` executed the injected write.
        const check = sandbox.exec(`cat ${mf} 2>/dev/null; rm -f ${mf}`, 5_000);
        if (check.stdout.includes(marker)) {
          exploits.push({
            attackClass: "command-injection",
            proof: "marker-executed",
            file,
            line: sinkLine,
            sink,
            summary: `Untrusted input to exported \`${name}()\` reaches a shell sink; an injected command executed (wrote a marker file), including via async/callback and class-method entrypoints.`,
            payload: `x; echo ${marker} > ${mf}`,
            evidence:
              `driver drove ${name}() across function/class-method/config-object shapes with a shell ` +
              `injection payload; the injected marker ${marker} was written to a file by a reached shell.`,
          });
          fired = true;
        }
      }
    }
    return exploits;
  }
}
