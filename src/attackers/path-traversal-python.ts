import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import {
  type Attacker,
  type StaticLead,
  PYTHON_SOURCE_RE,
  freshMarker,
  scanSinkLeads,
} from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// A path-traversal sink in Python: an `open(...)` on a path built with `os.path.join(...)` where one
// path segment is attacker-controlled. This is a lead; a finding is evidence of a real escape.
const SINK_RE = /\b(?:open|io\.open)\s*\(\s*[^,\n]*\b(?:os\.path\.join|pathlib\.Path)\s*\(/;

// The decoy traversal payloads are standard `../` escapes.
const TRAVERSAL_PAYLOADS = ["../raeuber-decoy.txt", "../../raeuber-decoy.txt", "../../../raeuber-decoy.txt"];

function firstSinkLine(source: string): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) if (SINK_RE.test(lines[i])) return i + 1;
  return 1;
}

interface PythonFn {
  name: string;
}

// Top-level entrypoints we can drive in isolation.
function topLevelFunctions(source: string): PythonFn[] {
  const re = /^def\s+([A-Za-z_]\w*)\s*\(\s*[A-Za-z_]\w*(?:\s*,[^)]*)?\)\s*:/gm;
  const names: string[] = [];
  for (const m of source.matchAll(re)) names.push(m[1]);
  return [...new Set(names)].map((name) => ({ name }));
}

function shq(s: string): string {
  return "'" + s.replace(/'/g, `'\\''`) + "'";
}

function pythonDriver(moduleFile: string, fnName: string): string {
  const mod = JSON.stringify("./" + moduleFile);
  const fn = JSON.stringify(fnName);
  return `
import base64
import os
import importlib.util

payload_b64 = os.environ.get("RAEUBER_PAYLOAD_B64", "")
try:
  payload = base64.b64decode(payload_b64).decode("utf-8", "replace")
except Exception as e:
  print("BASE64_FAIL:" + str(e))
  raise SystemExit(0)

spec = importlib.util.spec_from_file_location("raeuber_target", ${mod})
if spec is None or spec.loader is None:
  print("IMPORT_FAIL")
  raise SystemExit(0)

mod = importlib.util.module_from_spec(spec)
try:
  spec.loader.exec_module(mod)
except Exception as e:
  print("IMPORT_FAIL:" + str(e))
  raise SystemExit(0)

fn = getattr(mod, ${fn}, None)
if not callable(fn):
  print("NOT_A_FUNCTION")
  raise SystemExit(0)

try:
  fn(payload)
except Exception as e:
  print(str(e))
`.trim();
}

export class PathTraversalPythonAttacker implements Attacker {
  readonly attackClass = "path-traversal" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "path-traversal-python");
  // Python traversal payloading requires a Python runtime image in crabbox.
  readonly sandboxImage = "python:3-bookworm-slim";

  handles(file: string): boolean {
    return PYTHON_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    if (!SINK_RE.test(source)) return [];
    return scanSinkLeads(source, SINK_RE);
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
      if (!SINK_RE.test(source)) continue;

      const fns = topLevelFunctions(source);
      if (fns.length === 0) continue;
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "open").split("(")[0].trim();

      let fired = false;
      for (const fn of fns) {
        if (fired) break;
        const marker = freshMarker();
        const driverRel = `.raeuber-driver-${marker}.py`;
        sandbox.writeFile(driverRel, pythonDriver(file, fn.name));
        for (const payload of TRAVERSAL_PAYLOADS) {
          const out = sandbox.exec(
            `RAEUBER_PAYLOAD_B64=${Buffer.from(payload).toString("base64")} python3 ${shq(driverRel)} 2>&1`,
            15_000,
          );
          const output = out.stdout + out.stderr;
          if (output.includes(secret)) {
            exploits.push({
              attackClass: "path-traversal",
              proof: "secret-exfiltrated",
              file,
              line: sinkLine,
              sink,
              summary:
                `Untrusted first argument of \`${fn.name}()\` reaches a filesystem read with no ` +
                "containment; a `../` payload read the planted decoy secret.",
              payload,
              evidence:
                `driver called ${fn.name}(${JSON.stringify(payload)}); the planted marker ${secret} ` +
                `was returned to the caller:\n` +
                output.slice(0, 800),
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
