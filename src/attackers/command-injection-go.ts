import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, GO_SOURCE_RE, freshMarker, scanSinkLeads } from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// A command-injection sink in Go: an explicitly shell-driven `exec.Command("sh", "-c", cmd)` pattern.
const SHELL_COMMAND_RE =
  /\b(?:exec\.Command|exec\.CommandContext)\s*\(\s*(?:[^,]*,\s*)?(?:'|"|`)(?:\/(?:usr\/)?bin\/)?(?:sh|bash)(?:'|"|`)\s*,\s*(?:'|"|`)[^'"`]*-c[^'"`]*(?:'|"|`)\s*,/;
const SINK_RE = SHELL_COMMAND_RE;

function payloads(marker: string): string[] {
  return [
    `x; echo ${marker}`,
    `x$(echo ${marker})`,
    "`echo " + marker + "`",
    `x | echo ${marker}`,
    `x && echo ${marker}`,
  ];
}

/** Line number (1-indexed) of the first sink. */
function firstSinkLine(source: string): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) if (SINK_RE.test(lines[i])) return i + 1;
  return 1;
}

interface GoFn {
  name: string;
}

function packageName(source: string): string {
  const m = source.match(/^\s*package\s+([A-Za-z_]\w*)/m);
  return m ? m[1] : "main";
}

// Top-level entrypoints: `func name(arg string)` (any return type, one string arg minimum).
function stringArgFunctions(source: string): GoFn[] {
  const re = /^func\s+([A-Za-z_]\w*)\s*\(\s*[A-Za-z_]\w*\s+string\s*\)\s*/gm;
  const names: string[] = [];
  for (const m of source.matchAll(re)) names.push(m[1]);
  return [...new Set(names)].map((name) => ({ name }));
}

function shq(s: string): string {
  return "'" + s.replace(/'/g, `'\\''`) + "'";
}

function goDriver(fileFn: string, pkg: string): string {
  return `
package ${pkg}

import (
  "encoding/base64"
  "fmt"
  "os"
)

func main() {
  payloadB64 := os.Getenv("RAEUBER_PAYLOAD_B64")
  payloadBytes, err := base64.StdEncoding.DecodeString(payloadB64)
  if err != nil {
    fmt.Print(err)
    return
  }
  payload := string(payloadBytes)
  defer func() {
    if recovered := recover(); recovered != nil {
      fmt.Print(recovered)
    }
  }()
  fmt.Print(${fileFn}(payload))
}
`.trim();
}

export class CommandInjectionGoAttacker implements Attacker {
  readonly attackClass = "command-injection" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "command-injection-go");
  // Go command execution needs a Go-capable runtime image in crabbox.
  readonly sandboxImage = "golang:1.22-bookworm";

  handles(file: string): boolean {
    return GO_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    if (!SHELL_COMMAND_RE.test(source)) return []; // non-shell commands are not command-injection sinks
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
      if (!SHELL_COMMAND_RE.test(source) || !SINK_RE.test(source)) continue;
      const fns = stringArgFunctions(source);
      if (fns.length === 0) continue;
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "exec.Command").split("(")[0].trim();
      const pkg = packageName(source);

      let fired = false;
      for (const fn of fns) {
        if (fired) break;
        const marker = freshMarker();
        const payload = payloads(marker);
        const driverRel = `raeuber-driver-${marker}.go`;
        sandbox.writeFile(driverRel, goDriver(fn.name, pkg));
        for (const p of payload) {
          const run = sandbox.exec(
            `RAEUBER_PAYLOAD_B64=${Buffer.from(p).toString("base64")} go run ${shq(file)} ${shq(driverRel)} 2>&1`,
            30_000,
          );
          const out = run.stdout + run.stderr;
          const executed = out.replace(new RegExp(`echo\\s+${marker}`, "g"), "").includes(marker);
          if (executed) {
            exploits.push({
              attackClass: "command-injection",
              proof: "marker-executed",
              file,
              line: sinkLine,
              sink,
              summary:
                `Untrusted first argument of \`${fn.name}()\` reaches a shell command sink; an ` +
                `injected echo marker executed.`,
              payload: p,
              evidence:
                `driver called ${fn.name}(${JSON.stringify(p)}); the injected marker ${marker} ` +
                `appeared in shell output:\n` +
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
