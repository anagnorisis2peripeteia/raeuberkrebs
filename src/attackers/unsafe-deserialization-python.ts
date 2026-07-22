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
import {
  type DeserMode,
  PYTHON_SANDBOX_IMAGE,
  unsafeDeserPythonDriver,
  topLevelFunctions,
  shq,
} from "./python-driver.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// Unsafe-deserialization sinks in Python. Two families we can drive-and-prove:
//   - pickle-protocol loaders (pickle / cPickle / _pickle / dill / cloudpickle): unpickling executes
//     the payload's `__reduce__`, so attacker bytes run arbitrary code — the classic Python RCE.
//   - unsafe YAML loaders (`yaml.load` / `full_load` / `unsafe_load`, but NOT `safe_load`): construct
//     arbitrary Python objects from the document.
// These are only LEADS. The finding is a crafted payload whose deserialization fires a benign marker.
const PICKLE_RE = /\b(?:pickle|cPickle|_pickle|dill|cloudpickle)\s*\.\s*loads?\s*\(/;
const YAML_RE = /\byaml\s*\.\s*(?:load|full_load|unsafe_load)\s*\(/;
const SINK_RE = new RegExp(`${PICKLE_RE.source}|${YAML_RE.source}`);

function firstSinkLine(source: string): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) if (SINK_RE.test(lines[i])) return i + 1;
  return 1;
}

/** Which deserializer families this file uses — decides which gadget payloads the driver tries. */
function modesFor(source: string): DeserMode[] {
  const modes: DeserMode[] = [];
  if (PICKLE_RE.test(source)) modes.push("pickle");
  if (YAML_RE.test(source)) modes.push("yaml");
  return modes;
}

export class UnsafeDeserializationPythonAttacker implements Attacker {
  readonly attackClass = "unsafe-deserialization" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "unsafe-deserialization-python");
  readonly sandboxImage = PYTHON_SANDBOX_IMAGE;

  handles(file: string): boolean {
    return PYTHON_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    if (!SINK_RE.test(source)) return [];
    return scanSinkLeads(source, SINK_RE);
  }

  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
    const exploits: Exploit[] = [];
    const py = ensurePythonEnv(sandbox, targetDir);
    for (const file of files) {
      if (!this.handles(file)) continue;
      let source: string;
      try {
        source = readFileSync(join(targetDir, file), "utf8");
      } catch {
        continue;
      }
      if (!SINK_RE.test(source)) continue;

      const modes = modesFor(source);
      if (modes.length === 0) continue;
      const fns = topLevelFunctions(source);
      if (fns.length === 0) continue;
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "pickle.loads").split("(")[0].trim();

      let fired = false;
      for (const fn of fns) {
        if (fired) break;
        const marker = freshMarker();
        const driverRel = `.raeuber-deser-${marker}.py`;
        sandbox.writeFile(driverRel, unsafeDeserPythonDriver(file, fn.name, marker, modes));
        const out = sandbox.exec(`${py} ${shq(driverRel)} 2>&1`, 15_000);
        const output = out.stdout + out.stderr;
        const match = output.match(/UNSAFE_DESER_FIRED mode=(\w+)/);
        if (match) {
          const mode = match[1];
          exploits.push({
            attackClass: "unsafe-deserialization",
            proof: "marker-executed",
            file,
            line: sinkLine,
            sink,
            summary:
              `Untrusted first argument of \`${fn.name}()\` reaches an unsafe ${mode} deserializer; ` +
              `a crafted payload executed a benign gadget during deserialization.`,
            payload: mode === "pickle" ? "pickle.dumps(gadget __reduce__ -> open(sentinel))" : `!!python/object/apply:builtins.open [sentinel]`,
            evidence:
              `driver called ${fn.name}(<${mode} gadget>); deserialization executed the gadget, which ` +
              `created the sentinel file (echo-proof side effect). Driver output:\n` +
              output.slice(0, 800),
          });
          fired = true;
        }
      }
    }
    return exploits;
  }
}
