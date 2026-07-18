import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, freshMarker, scanSinkLeads } from "./attacker.js";
import {
  DOTNET_SOURCE_RE,
  DOTNET_ENV,
  dotnetTfm,
  csharpDrivableMethods,
  dotnetDriverCsproj,
  dotnetDriverProgram,
} from "./dotnet.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// A command-injection sink in C#: a process launch (`Process.Start`, `new ProcessStartInfo`,
// or a `ProcessStartInfo { ... }` initializer). This is only a LEAD; the finding is a fired payload.
const SINK_RE = /\bProcess\.Start\b|\bnew\s+ProcessStartInfo\b|\bProcessStartInfo\s*\{/;

// The launched file/args are built from a variable (concatenation or `$"…"` interpolation) rather
// than a fixed literal — the tainted shape that makes the sink injectable. Mirrors the Node lane's
// requirement that the command string isn't a constant (a fully-literal `Process.Start` can't inject).
const TAINT_RE = /(?:Arguments|FileName)\s*=\s*(?:[^;\n]*\$@?"|[^;\n]*"[^;\n]*\+|[^;\n]*\b[A-Za-z_]\w*\s*\+)/;

/** POSIX single-quote so a payload's shell metacharacters reach the C# sink verbatim instead of being
 *  expanded by the sandbox's own outer shell. */
function shq(s: string): string {
  return "'" + s.replace(/'/g, `'\\''`) + "'";
}

// Benign proof-of-execution payloads: each injects `echo <marker>` via a different metacharacter,
// spanning POSIX `sh` (`;`, `&&`, `|`, `$()`, backtick) and Windows `cmd` (`&&`, `|`, `&`). Firing
// means the injected echo ran — the vuln is proven, nothing is harmed.
function payloads(marker: string): string[] {
  return [
    `x; echo ${marker}`,
    `x && echo ${marker}`,
    `x | echo ${marker}`,
    `x& echo ${marker}`,
    `x$(echo ${marker})`,
    `x\`echo ${marker}\``,
  ];
}

/** Line number (1-indexed) of the first sink, for the evidence trail. */
function firstSinkLine(source: string): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) if (SINK_RE.test(lines[i])) return i + 1;
  return 1;
}

/**
 * The .NET command-injection lane. Same contract and cardinal rule as the Node lane — a finding is a
 * payload that EXECUTED and echoed its unique marker — but it drives a compiled entrypoint: it builds
 * the changed file plus a generated driver into an isolated single-file console project and runs it
 * once per payload. Its canary is a planted-vulnerable C# fixture it must fire against, or the lane
 * is quarantined (fail-closed).
 */
export class CommandInjectionDotnetAttacker implements Attacker {
  readonly attackClass = "command-injection" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "command-injection-dotnet");

  handles(file: string): boolean {
    return DOTNET_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    if (!TAINT_RE.test(source)) return []; // fully-literal process launch → not injectable
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
      if (!SINK_RE.test(source)) continue; // no process sink — nothing to drive
      if (!TAINT_RE.test(source)) continue; // sink is fully literal — not injectable
      const methods = csharpDrivableMethods(source);
      if (methods.length === 0) continue; // reachable sink but no public string-first-arg entrypoint
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "Process.Start").trim();

      let fired = false;
      for (const method of methods) {
        if (fired) break;
        const marker = freshMarker();
        const dir = `.rk-dotnet-${marker}`;
        const asm = "rkdrv";

        // Assemble an isolated one-file project: the target source + the generated driver + a csproj.
        sandbox.exec(`mkdir -p ${dir}`, 10_000);
        sandbox.writeFile(`${dir}/Target.cs`, source);
        sandbox.writeFile(`${dir}/Driver.cs`, dotnetDriverProgram(method));
        sandbox.writeFile(`${dir}/drv.csproj`, dotnetDriverCsproj(asm));

        sandbox.exec(`${DOTNET_ENV} dotnet build ${dir}/drv.csproj -c Release -v quiet 2>&1`, 180_000);
        const dll = `${dir}/bin/Release/${dotnetTfm()}/${asm}.dll`;
        // Gate on the artifact existing, not on parsing build text (robust across sandbox providers).
        // No dll ⇒ the file needs its project's deps to compile — not drivable in isolation; skip it
        // (an honest miss, never a false pass).
        const check = sandbox.exec(`test -f ${dll} && echo RK_DLL_OK || echo RK_NO_DLL`, 10_000);
        if (!check.stdout.includes("RK_DLL_OK")) continue;

        for (const payload of payloads(marker)) {
          const run = sandbox.exec(`${DOTNET_ENV} dotnet ${dll} ${shq(payload)} 2>&1`, 30_000);
          const out = run.stdout + run.stderr;
          // Fired = the marker appears OUTSIDE the literal `echo <marker>` we injected. If the app
          // merely echoed our payload back verbatim, the only occurrence is that literal (stripped
          // here) → false, no false positive. If the injection executed, the child's bare `<marker>`
          // survives the strip.
          const executed = out.replace(new RegExp(`echo\\s+${marker}`, "g"), "").includes(marker);
          if (executed) {
            exploits.push({
              attackClass: "command-injection",
              proof: "marker-executed",
              file,
              line: sinkLine,
              sink,
              summary: `Untrusted first argument of public \`${method.className}.${method.name}()\` reaches a process/shell sink; an injected echo executed.`,
              payload,
              evidence:
                `driver invoked ${method.className}.${method.name}(${JSON.stringify(payload)}); ` +
                `the injected marker ${marker} appeared in child-process output:\n` +
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
