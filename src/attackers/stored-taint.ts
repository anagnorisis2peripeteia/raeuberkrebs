import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, NODE_RUN, NODE_SOURCE_RE, freshMarker, nodeExportedNames } from "./attacker.js";
import { functionUnits } from "./broken-access-control.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// Stored taint / second-order (CWE-20): attacker-shaped input is written (often after light
// sanitization) into persistent storage, then read back without re-validation. A stored value surviving
// this read is the proof signal.

// Name heuristics for writer / reader entrypoints.
const WRITE_NAME_RE =
  /^(?:create|add|new|make|register|save|store|persist|upsert|insert|write|set|issue|mint|upload)/i;
const READ_NAME_RE = /^(?:get|read|fetch|load|lookup|select|describe|show|view|open|resolve|export)/i;

// Body heuristics for storage sinks/sources.
const WRITE_BODY_RE =
  /\[[^\]]+\]\s*=|\.set(?:Item)?\s*\(|\.push\s*\(|\.(?:save|store|persist|upsert|insert|write|add|set)\s*\(|\bMap\.prototype\.set\s*\(/i;
const READ_BODY_RE = /\[[^\]]+\]|\.get(?:Item)?\s*\(|\.(?:load|read|fetch|find|select)\s*\(/i;

const WRITE_SINK_RE = /(?:\[[^\]]+\]\s*=|\.set(?:Item)?\s*\(|\.(?:save|store|persist|upsert|insert|write|add|set)\s*\()/i;
const READ_SINK_RE = /(?:\[[^\]]+\]|\.get(?:Item)?\s*\(|\.(?:load|read|fetch|find|select|open|resolve|lookup)\s*\()/i;

interface Entry {
  name: string;
  line: number;
  body: string;
  canWrite: boolean;
  canRead: boolean;
}

function collectStorageLeads(source: string): StaticLead[] {
  const leads: StaticLead[] = [];
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    if (WRITE_SINK_RE.test(line)) leads.push({ line: i + 1, sink: "storage-write" });
    if (READ_SINK_RE.test(line)) leads.push({ line: i + 1, sink: "storage-read" });
  }
  return leads;
}

function storedTaintDriver(moduleRel: string, writerName: string, readerName: string, marker: string): string {
  const mod = JSON.stringify("./" + moduleRel);
  const W = JSON.stringify(writerName);
  const R = JSON.stringify(readerName);
  const MK = JSON.stringify(marker);
  return `
const MARKER = ${MK};
let m;
try { m = await import(${mod}); } catch (e) { process.stdout.write("IMPORT_FAIL:" + e); process.exit(0); }
function pick(n){
  if (m && typeof m[n]==="function") return m[n];
  if (m && m.default && typeof m.default[n]==="function") return m.default[n];
  return null;
}
const writer = pick(${W}), reader = pick(${R});
if (!writer || !reader) { process.stdout.write("NOT_A_FUNCTION"); process.exit(0); }

const MARKER_KEY = "record-" + MARKER;
const payload = { key: MARKER_KEY, id: MARKER_KEY, data: MARKER, body: MARKER, text: MARKER, value: MARKER };
const contexts = [
  { identity: "writer-" + MARKER, userId: "writer-" + MARKER, scopes: ["write"] },
  { actor: "writer-" + MARKER },
  { user: { id: "writer-" + MARKER } },
  { ctx: "writer-" + MARKER },
  {},
];

function collectIds(v, out){
  if (v == null) return;
  if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
    out.push(String(v));
    return;
  }
  if (Array.isArray(v)) {
    for (const item of v) collectIds(item, out);
    return;
  }
  if (typeof v !== "object") return;
  for (const key of Object.keys(v)) {
    if (typeof key === "string") out.push(key);
    const val = v[key];
    if (typeof val === "object" || Array.isArray(val)) collectIds(val, out);
    else if (typeof key !== "undefined" && /^(id|key|sessionId|recordId|recordKey|_id|uuid|name)$/i.test(key)) out.push(val);
  }
}

function toText(v){
  try {
    return typeof v === "string" ? v : JSON.stringify(v);
  } catch {
    return String(v || "");
  }
}

function hasMarker(v){
  const text = toText(v);
  return String(text).indexOf(MARKER) !== -1;
}

async function call(fn, args){
  try { return { ok: true, ret: await fn(...args) }; } catch { return { ok: false, ret: null }; }
}

const writeIds = [];
const writeShapes = [
  [payload],
  [contexts[0], payload],
  [payload, contexts[0]],
  [payload.key],
  [contexts[1], payload.key],
  [payload.key, contexts[1]],
];
for (const args of writeShapes){
  const r = await call(writer, args);
  if (!r.ok) continue;
  const wrote = r.ret;
  collectIds(wrote, writeIds);
  if (hasMarker(wrote)) writeIds.push(MARKER_KEY);
}
collectIds(payload.key, writeIds);
collectIds(payload.id, writeIds);
if (hasMarker(payload.value)) writeIds.push(MARKER_KEY);

const keyCandidates = [...new Set(writeIds.map((v) => String(v).trim()).filter(Boolean))];

const readShapes = (id) => [
  [id],
  [contexts[0], id],
  [id, contexts[0]],
  [contexts[2], id],
  [id, contexts[2]],
  [{ id }, contexts[0]],
  [{ key: id }, contexts[0]],
  [contexts[2], { id }],
  [{ key: id }],
];

for (const id of keyCandidates){
  for (const args of readShapes(id)) {
    const rr = await call(reader, args);
    if (!rr.ok) continue;
    if (hasMarker(rr.ret)) {
      process.stdout.write("STORED_TAINT_FIRED write=" + ${W} + " read=" + ${R} + " key=" + id);
      process.exit(0);
    }
  }
}
process.stdout.write("no-stored-taint");
`.trim();
}

export class StoredTaintAttacker implements Attacker {
  readonly attackClass = "stored-taint" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "stored-taint-node");

  handles(file: string): boolean {
    return NODE_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    return collectStorageLeads(source);
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
      const entries: Entry[] = functionUnits(source)
        .filter((u) => exported.has(u.name))
        .map((u) => ({
          name: u.name,
          line: u.line,
          body: u.body,
          canWrite: WRITE_NAME_RE.test(u.name) || WRITE_BODY_RE.test(u.body),
          canRead: READ_NAME_RE.test(u.name) || READ_BODY_RE.test(u.body),
        }));

      const writers = entries.filter((u) => u.canWrite);
      const readers = entries.filter((u) => u.canRead);
      if (writers.length === 0 || readers.length === 0) continue;

      let fired = false;
      for (const writer of writers) {
        if (fired) break;
        for (const reader of readers) {
          if (writer.name === reader.name) continue;
          const marker = freshMarker();
          const driverRel = `.raeuber-stored-taint-${marker}.mjs`;
          sandbox.writeFile(driverRel, storedTaintDriver(file, writer.name, reader.name, marker));
          const run = sandbox.exec(`${NODE_RUN} ${driverRel} 2>&1`, 15_000);
          const out = run.stdout + run.stderr;
          if (!out.includes("STORED_TAINT_FIRED")) continue;

          exploits.push({
            attackClass: "stored-taint",
            proof: "secret-exfiltrated",
            file,
            line: reader.line,
            sink: `stored-taint(${reader.name})`,
            summary:
              `Exported writer \`${writer.name}()\` persists attacker-shaped input and reader \`${reader.name}()\` reads it back without re-validation; ` +
              "a fresh marker written through one entrypoint was returned on read, demonstrating second-order stored taint.",
            payload: `${writer.name}(payload) → ${reader.name}(marker key)`,
            evidence:
              `driver wrote marker ${marker} through \`${writer.name}()\` and observed it return through \`${reader.name}()\`: ` +
              out.slice(0, 700),
          });
          fired = true;
          break;
        }
      }
    }
    return exploits;
  }
}
