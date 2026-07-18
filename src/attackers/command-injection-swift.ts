import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, freshMarker, scanSinkLeads } from "./attacker.js";
import { SWIFT_SOURCE_RE, swiftDrivableFunctions, swiftDriverMain } from "./swift.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// A command-injection sink in Swift: a subprocess launch — `Process()` (Foundation), its
// executable/launch setters, or a raw `posix_spawn(p)`. This is only a LEAD; the finding is a fired
// payload.
const SINK_RE = /\bProcess\s*\(\s*\)|\bProcess\.launchedProcess\b|\bposix_spawnp?\b|\.executableURL\s*=|\.launchPath\s*=/;

// The launched command/args are built from a variable — a Swift string interpolation `\(…)` or a
// `+` concatenation — rather than a fixed literal. That is the tainted shape that makes the sink
// injectable (mirrors the Node/`.NET` requirement that the command isn't a constant). The classic
// vector is an interpolated `-c` shell string: `arguments = ["-c", "cmd \(userInput)"]`.
const TAINT_RE = /\\\(|["'][^"'\n]*["']\s*\+\s*[A-Za-z_]|[A-Za-z_]\w*\s*\+\s*["']/;

/** POSIX single-quote so a payload's shell metacharacters reach the Swift sink verbatim instead of
 *  being expanded by the sandbox's own outer shell. */
function shq(s: string): string {
  return "'" + s.replace(/'/g, `'\\''`) + "'";
}

// Benign proof-of-execution payloads: each injects `echo <marker>` via a different POSIX shell
// metacharacter (`;`, `&&`, `|`, `$()`, backtick). Firing means the injected echo ran — the vuln is
// proven, nothing is harmed (the Swift sinks shell out through `/bin/sh`/`/bin/bash`).
function payloads(marker: string): string[] {
  return [
    `x; echo ${marker}`,
    `x && echo ${marker}`,
    `x | echo ${marker}`,
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
 * The Swift command-injection lane. Same contract and cardinal rule as the Node/`.NET` lanes — a
 * finding is a payload that EXECUTED and echoed its unique marker — but it drives a compiled Swift
 * entrypoint: it compiles the changed file together with a generated `main.swift` driver into an
 * isolated executable and runs it once per payload. Its canary is a planted-vulnerable Swift fixture
 * it must fire against, or the lane is quarantined (fail-closed). Swift compiles/runs natively on the
 * macOS host (the local sandbox); AppKit-linked app code won't cross-compile to the Linux crabbox box.
 */
export class CommandInjectionSwiftAttacker implements Attacker {
  readonly attackClass = "command-injection" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "command-injection-swift");

  handles(file: string): boolean {
    return SWIFT_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    if (!TAINT_RE.test(source)) return []; // fully-literal subprocess launch → not injectable
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
      if (!SINK_RE.test(source)) continue; // no subprocess sink — nothing to drive
      if (!TAINT_RE.test(source)) continue; // sink is fully literal — not injectable
      const fns = swiftDrivableFunctions(source);
      if (fns.length === 0) continue; // reachable sink but no drivable string-first-arg entrypoint
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "Process()").trim();

      let fired = false;
      for (const fn of fns) {
        if (fired) break;
        const marker = freshMarker();
        const dir = `.rk-swift-${marker}`;
        const bin = `${dir}/drv`;

        // Assemble an isolated build: the target source + the generated driver, compiled together so
        // the driver can call the (same-module) entrypoint. `main.swift` carries the top-level code.
        sandbox.exec(`mkdir -p ${dir}`, 10_000);
        sandbox.writeFile(`${dir}/Target.swift`, source);
        sandbox.writeFile(`${dir}/main.swift`, swiftDriverMain(fn));

        sandbox.exec(`swiftc -suppress-warnings ${dir}/Target.swift ${dir}/main.swift -o ${bin} 2>&1`, 180_000);
        // Gate on the artifact existing, not on parsing compiler text (robust across providers). No
        // binary ⇒ the file needs the rest of its package to compile — not drivable in isolation;
        // skip it (an honest miss, never a false pass).
        const check = sandbox.exec(`test -f ${bin} && echo RK_BIN_OK || echo RK_NO_BIN`, 10_000);
        if (!check.stdout.includes("RK_BIN_OK")) continue;

        for (const payload of payloads(marker)) {
          const run = sandbox.exec(`./${bin} ${shq(payload)} 2>&1`, 30_000);
          const out = run.stdout + run.stderr;
          // Fired = the marker appears OUTSIDE the literal `echo <marker>` we injected. If the app
          // merely echoed our payload back verbatim, the only occurrence is that literal (stripped
          // here) → false, no false positive. If the injection executed, the child's bare `<marker>`
          // survives the strip.
          const executed = out.replace(new RegExp(`echo\\s+${marker}`, "g"), "").includes(marker);
          if (executed) {
            const receiver = fn.enclosingType ? `${fn.enclosingType}.${fn.name}` : fn.name;
            exploits.push({
              attackClass: "command-injection",
              proof: "marker-executed",
              file,
              line: sinkLine,
              sink,
              summary: `Untrusted first argument of \`${receiver}()\` reaches a subprocess/shell sink; an injected echo executed.`,
              payload,
              evidence:
                `driver invoked ${receiver}(${JSON.stringify(payload)}); ` +
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
