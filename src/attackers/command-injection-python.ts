import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import { type Sandbox, ensurePythonEnv } from "../sandbox.js";
import {
  type Attacker,
  type StaticLead,
  PYTHON_SOURCE_RE,
  freshMarker,
  scanSinkLeads,
} from "./attacker.js";
import { PYTHON_SANDBOX_IMAGE, pythonDriver, topLevelFunctions, shq } from "./python-driver.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// A command-injection sink in Python: `subprocess(..., shell=True)` and `os.system(...)`.
// This lane drives command strings that pass through a shell; command-assembly sinks that are
// non-shell are outside this primitive and are tracked elsewhere.
const SINK_RE =
  /\b(?:subprocess\.(?:run|Popen|call|check_output|check_call)\s*\(|os\.system\s*\()/;
const SHELL_RE =
  /\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\([^)]*shell\s*=\s*True\b/;

function payloads(marker: string): string[] {
  return [
    `x; echo ${marker}`,
    `x$(echo ${marker})`,
    `x\`echo ${marker}\``,
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

export class CommandInjectionPythonAttacker implements Attacker {
  readonly attackClass = "command-injection" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "command-injection-python");
  readonly sandboxImage = PYTHON_SANDBOX_IMAGE;

  handles(file: string): boolean {
    return PYTHON_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    if (!SHELL_RE.test(source)) return []; // non-shell subprocess usage is not shell injection.
    return scanSinkLeads(source, SINK_RE);
  }

  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
    const exploits: Exploit[] = [];
    // Resolve the python to drive with once per sandbox (opt-in venv so real-package deps import).
    const py = ensurePythonEnv(sandbox, targetDir);
    for (const file of files) {
      if (!this.handles(file)) continue;
      let source: string;
      try {
        source = readFileSync(join(targetDir, file), "utf8");
      } catch {
        continue;
      }
      if (!SINK_RE.test(source) || !SHELL_RE.test(source)) continue;

      const fns = topLevelFunctions(source);
      if (fns.length === 0) continue;
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "subprocess.run").split("(")[0].trim();

      let fired = false;
      for (const fn of fns) {
        if (fired) break;
        const marker = freshMarker();
        for (const payload of payloads(marker)) {
          const driverRel = `.raeuber-driver-${marker}.py`;
          sandbox.writeFile(driverRel, pythonDriver(file, fn.name));
          const out = sandbox.exec(
            `RAEUBER_PAYLOAD_B64=${Buffer.from(payload).toString("base64")} ${py} ${shq(driverRel)} 2>&1`,
            15_000,
          );
          const output = out.stdout + out.stderr;
          const executed = output.replace(new RegExp(`echo\\s+${marker}`, "g"), "").includes(marker);
          if (executed) {
            exploits.push({
              attackClass: "command-injection",
              proof: "marker-executed",
              file,
              line: sinkLine,
              sink,
              summary:
                `Untrusted first argument of exported \`${fn.name}()\` reaches a shell sink; an injected ` +
                `echo marker executed.`,
              payload,
              evidence:
                `driver called ${fn.name}(${JSON.stringify(payload)}); the injected marker ${marker} ` +
                `appeared in command output:\n` +
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
