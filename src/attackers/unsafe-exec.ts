import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import {
  type Attacker,
  type StaticLead,
  NODE_RUN,
  NODE_SOURCE_RE,
  freshMarker,
  nodeExportedNames,
  nodeImportDriver,
} from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// Unsafe dynamic execution sinks in Node: direct `eval`, dynamic `Function` constructors, and VM
// `runIn*` APIs. We only treat the call as a lead when the first argument is variable / variable-shaped,
// not a plain literal constant.
const DYNAMIC_EXEC_RE = /(?:eval|new\s+Function|vm\.runIn[A-Za-z]+)\s*\(\s*([^,\)]*)/;

function argLooksVariable(argument: string): boolean {
  const arg = argument.trim();
  if (!arg) return false;
  // Plain string literals are fixed code paths. Only template literals with `${...}` remain variable.
  if (arg.startsWith("'") || arg.startsWith('"')) {
    return /\+\s*[A-Za-z_$][\w$]*|[A-Za-z_$][\w$]*\s*\+/.test(arg);
  }
  if (arg.startsWith("`")) return /\$\{/.test(arg);
  // Numeric/boolean literals and standalone operators are non-variable. Any identifier token indicates
  // a variable-shaped source for the payload.
  return /[A-Za-z_$][\w$]*/.test(arg);
}

function markerPayload(marker: string): { marker: string; payload: string }[] {
  const charCodes = [...marker].map((ch) => ch.charCodeAt(0));
  const expr = `String.fromCharCode(${charCodes.join(",")})`;
  return [
    { marker, payload: expr }, // `eval`/`vm.runIn*` can evaluate this expression and return the marker string
    { marker, payload: `return ${expr};` }, // `new Function` sinks usually execute via a returned function body
  ];
}

function firstUnsafeExecSink(source: string): { line: number; sink: string } | null {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(DYNAMIC_EXEC_RE);
    if (!m) continue;
    if (!argLooksVariable(m[1] ?? "")) continue;
    const sink = (m[0].match(/(?:eval|new\s+Function|vm\.runIn[A-Za-z]+)/) ?? ["<sink>"])[0];
    return { line: i + 1, sink };
  }
  return null;
}

export class UnsafeExecAttacker implements Attacker {
  readonly attackClass = "unsafe-exec" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "unsafe-exec-node");

  handles(file: string): boolean {
    return NODE_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    const leads: StaticLead[] = [];
    const lines = source.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(DYNAMIC_EXEC_RE);
      if (!m) continue;
      if (!argLooksVariable(m[1] ?? "")) continue;
      const sink = (lines[i].match(/(?:eval|new\s+Function|vm\.runIn[A-Za-z]+)/) ?? [])[0];
      if (sink) leads.push({ line: i + 1, sink: sink.trim() });
    }
    return leads;
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
      const sink = firstUnsafeExecSink(source);
      if (!sink) continue;
      const names = nodeExportedNames(source);
      if (names.length === 0) continue;

      for (const name of names) {
        let fired = false;
        for (const candidate of markerPayload(freshMarker())) {
          const driverRel = `.raeuber-driver-${freshMarker()}.mjs`;
          sandbox.writeFile(driverRel, nodeImportDriver(file, name, candidate.payload));
          const run = sandbox.exec(`${NODE_RUN} ${driverRel} 2>&1`, 15_000);
          const out = run.stdout + run.stderr;
          if (out.includes(candidate.marker)) {
            exploits.push({
              attackClass: "unsafe-exec",
              proof: "marker-executed",
              file,
              line: sink.line,
              sink: sink.sink,
              summary:
                `Untrusted first argument of exported \`${name}()\` reaches unsafe dynamic execution (` +
                `${sink.sink}); the injected marker was reconstructed and observed.`,
              payload: candidate.payload,
              evidence:
                `driver called ${name}(${JSON.stringify(candidate.payload)}); the canary returned/printed ` +
                `marker ${candidate.marker}:\n` +
                out.slice(0, 800),
            });
            fired = true;
            break;
          }
        }
        if (fired) break;
      }
    }
    return exploits;
  }
}
