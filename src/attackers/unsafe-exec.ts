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
// `runIn*` APIs. We only treat the sink argument as variable-shaped when it appears to come from
// runtime data rather than a fixed literal.
const DYNAMIC_EXEC_RE = /\b(?:eval|new\s+Function|vm\.runIn[A-Za-z]+)\s*\(\s*([^)]*)\)/;

const IDENT_RE = /[A-Za-z_$][\w$]*/;

function splitTopLevelArgs(args: string): string[] {
  const chunks: string[] = [];
  let depth = 0;
  let quote: "'" | '"' | '`' | null = null;
  let escaped = false;
  let start = 0;

  for (let i = 0; i < args.length; i++) {
    const ch = args[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote) {
      if (ch === "\\") {
        escaped = true;
        continue;
      }
      if (ch === quote) {
        quote = null;
      }
      continue;
    }

    if (ch === "'" || ch === '"' || ch === "`") {
      quote = ch;
      continue;
    }
    if (ch === "(" || ch === "{" || ch === "[") depth++;
    else if (ch === ")" || ch === "}" || ch === "]") depth = Math.max(0, depth - 1);
    else if (ch === "," && depth === 0) {
      chunks.push(args.slice(start, i));
      start = i + 1;
    }
  }

  chunks.push(args.slice(start));
  return chunks;
}

function removeStringyTokens(source: string): string {
  return source
    .replace(/"(?:\\.|[^"\\])*"/g, "")
    .replace(/'(?:\\.|[^'\\])*'/g, "")
    .replace(/`(?:\\.|[^`\\])*`/g, "")
    .replace(/\/\*[^]*?\*\//g, "")
    .replace(/\/\/.*$/gm, "")
    .replace(/\/(?:\\.|[^\\/])+\/[gimsuy]*/g, "");
}

function hasIdentifierToken(argument: string): boolean {
  return IDENT_RE.test(removeStringyTokens(argument));
}

function argLooksVariable(argument: string): boolean {
  const arg = argument.trim();
  if (!arg) return false;
  // Plain string literals are fixed code paths. Only template literals with `${...}` remain variable.
  if (arg.startsWith("'") || arg.startsWith('"')) {
    return hasIdentifierToken(arg);
  }
  if (arg.startsWith("`")) {
    const exprs = arg.match(/\$\{[^}]*\}/g);
    if (!exprs || exprs.length === 0) return false;
    return exprs.some((expr) => hasIdentifierToken(expr.slice(2, -1)));
  }
  // Numeric/boolean literals and standalone operators are non-variable. Any identifier token indicates
  // a variable-shaped source for the payload.
  return hasIdentifierToken(arg);
}

function selectedArgForDynamicExec(line: string, sink: string): string | null {
  const rawArgMatch = line.match(DYNAMIC_EXEC_RE);
  if (!rawArgMatch) return null;
  const rawArgs = rawArgMatch[1] ?? "";
  const args = splitTopLevelArgs(rawArgs).map((arg) => arg.trim()).filter(Boolean);
  if (args.length === 0) return null;
  if (sink.replace(/\s+/g, "") === "newFunction") return args[args.length - 1] ?? null;
  return args[0] ?? null;
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
    const line = lines[i];
    const matchedSink = line.match(/(?:eval|new\s+Function|vm\.runIn[A-Za-z]+)/);
    if (!matchedSink) continue;
    const sink = matchedSink[0];
    const selectedArg = selectedArgForDynamicExec(line, sink);
    if (!selectedArg || !argLooksVariable(selectedArg)) continue;
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
      const line = lines[i];
      const matchedSink = line.match(/(?:eval|new\s+Function|vm\.runIn[A-Za-z]+)/);
      if (!matchedSink) continue;
      const sink = matchedSink[0];
      const selectedArg = selectedArgForDynamicExec(line, sink);
      if (!selectedArg || !argLooksVariable(selectedArg)) continue;
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
                `Untrusted sink argument of exported \`${name}()\` reaches unsafe dynamic execution (` +
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
