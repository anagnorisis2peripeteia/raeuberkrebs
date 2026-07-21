import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, GO_SOURCE_RE, freshMarker } from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// A path-traversal sink in Go: a filesystem read using an untrusted path component joined via
// `filepath.Join` and passed to a read/open API (`os.ReadFile`, `os.Open`, etc.).
const SINK_DIRECT_RE =
  /\b(?:os\.ReadFile|os\.Open|os\.OpenFile|os\.ReadFileFS|os\.ReadDir)\s*\([^)]*filepath\.Join\s*\(/;
const SINK_RE = SINK_DIRECT_RE;
const READ_SINK_RE = /\b(?:os\.ReadFile|os\.Open|os\.OpenFile|os\.ReadFileFS|os\.ReadDir)\s*\(/;
const JOIN_ASSIGN_RE = /\b([A-Za-z_]\w*)\s*(?::=|=)\s*[^;\n]*\bfilepath\.Join\s*\(/;

const TRAVERSAL_PAYLOADS = ["../raeuber-decoy.txt", "../../raeuber-decoy.txt", "../../../raeuber-decoy.txt"];

function firstSinkLine(source: string): number {
  const lines = source.split("\n");
  const joined = joinAssignedVars(source);
  for (let i = 0; i < lines.length; i++) {
    if (SINK_DIRECT_RE.test(lines[i])) return i + 1;
    if (isJoinedReadSink(lines[i], joined)) return i + 1;
  }
  return 1;
}

function joinAssignedVars(source: string): Set<string> {
  const vars = new Set<string>();
  for (const line of source.split("\n")) {
    const m = line.match(JOIN_ASSIGN_RE);
    if (m && m[1]) vars.add(m[1]);
  }
  return vars;
}

function isJoinedReadSink(line: string, joined: Set<string>): boolean {
  if (!READ_SINK_RE.test(line)) return false;
  if (/filepath\.Join/.test(line)) return true;

  const readCall = line.match(/\b(?:os\.ReadFile|os\.Open|os\.OpenFile|os\.ReadFileFS|os\.ReadDir)\s*\(\s*([^)]*)/);
  if (!readCall) return false;
  const firstArg = (readCall[1] ?? "").split(",")[0] ?? "";
  if (!firstArg.trim()) return false;
  for (const name of joined) {
    if (new RegExp(`\\b${name}\\b`).test(firstArg)) return true;
  }
  return false;
}

function hasTraversalSink(source: string): boolean {
  const joined = joinAssignedVars(source);
  return source.split("\n").some((line) => SINK_DIRECT_RE.test(line) || isJoinedReadSink(line, joined));
}

function traversalLeads(source: string): StaticLead[] {
  const joined = joinAssignedVars(source);
  const lines = source.split("\n");
  const leads: StaticLead[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    const sinkCall = line.match(/\b(?:os\.ReadFile|os\.Open|os\.OpenFile|os\.ReadFileFS|os\.ReadDir)\s*\(/);
    if (SINK_DIRECT_RE.test(line) || isJoinedReadSink(line, joined)) {
      leads.push({ line: i + 1, sink: sinkCall ? sinkCall[0].split("(")[0].trim() : "os.ReadFile" });
    }
  }
  return leads;
}

interface GoFn {
  name: string;
}

// Top-level entrypoints: `func name(arg string)` (any return type).
function stringArgFunctions(source: string): GoFn[] {
  const re = /^func\s+([A-Za-z_]\w*)\s*\(\s*[A-Za-z_]\w*\s+string\s*\)\s*/gm;
  const names: string[] = [];
  for (const m of source.matchAll(re)) names.push(m[1]);
  return [...new Set(names)].map((name) => ({ name }));
}

function packageName(source: string): string {
  const m = source.match(/^\s*package\s+([A-Za-z_]\w*)/m);
  return m ? m[1] : "main";
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

export class PathTraversalGoAttacker implements Attacker {
  readonly attackClass = "path-traversal" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "path-traversal-go");
  // Go path traversal payloading requires a Go runtime image in crabbox.
  readonly sandboxImage = "golang:1.22-bookworm";

  handles(file: string): boolean {
    return GO_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    if (!hasTraversalSink(source)) return [];
    return traversalLeads(source);
  }

  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
    const exploits: Exploit[] = [];
    const secret = freshMarker() + "_PT_SECRET";
    sandbox.writeFile("raeuber-decoy.txt", secret);
    for (const file of files) {
      if (!this.handles(file)) continue;
      let source: string;
      try {
        source = readFileSync(join(targetDir, file), "utf8");
      } catch {
        continue;
      }
      if (!hasTraversalSink(source)) continue;
      const fns = stringArgFunctions(source);
      if (fns.length === 0) continue;
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "os.ReadFile").split("(")[0].trim();
      const pkg = packageName(source);

      let fired = false;
      for (const fn of fns) {
        if (fired) break;
        const marker = freshMarker();
        const driverRel = `raeuber-driver-${marker}.go`;
        sandbox.writeFile(driverRel, goDriver(fn.name, pkg));
        for (const payload of TRAVERSAL_PAYLOADS) {
          const run = sandbox.exec(
            `RAEUBER_PAYLOAD_B64=${Buffer.from(payload).toString("base64")} go run ${shq(file)} ${shq(driverRel)} 2>&1`,
            30_000,
          );
          const out = run.stdout + run.stderr;
          if (out.includes(secret)) {
            exploits.push({
              attackClass: "path-traversal",
              proof: "secret-exfiltrated",
              file,
              line: sinkLine,
              sink,
              summary:
                `Untrusted first argument of \`${fn.name}()\` reaches a filesystem read with no containment ` +
                "and can read the decoy secret outside the intended base.",
              payload,
              evidence:
                `driver called ${fn.name}(${JSON.stringify(payload)}); the planted decoy marker ` +
                `${secret} was read from outside base:\n` +
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
