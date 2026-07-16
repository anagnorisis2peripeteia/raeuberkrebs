import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, NODE_RUN, NODE_SOURCE_RE, freshMarker, nodeExportedNames, scanSinkLeads } from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// A CSV/spreadsheet-serialization sink: a hand-rolled `.join(",")` over mapped rows, a csv library
// (csv-stringify / papaparse `unparse` / fast-csv), or a write to a `.csv` file. A lead, not a
// finding — whether an untrusted cell survives WITHOUT formula-prefix neutralization is what the PoC
// decides. (Modelled on openclaw's google-meet `csvCell`, which quote-escapes but doesn't guard
// leading `= + - @`.)
const SINK_RE =
  /\.join\(\s*(['"]),\1\s*\)|\bunparse\s*\(|csv[_-]?stringify|\bstringify\s*\([^)]*\b(?:columns|header|delimiter)\b|(?:writeFileSync?|createWriteStream)\s*\([^)]*\.csv/i;

function firstSinkLine(source: string): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) if (SINK_RE.test(lines[i])) return i + 1;
  return 1;
}

/**
 * CSV/formula-injection is unusual: the payload fires in the VICTIM's spreadsheet, not our sandbox.
 * So the proof is that a benign formula marker `=RAEUBER_<m>` SURVIVES into the produced output as a
 * cell that still BEGINS with a formula trigger (`= + - @`) — un-neutralized. This driver imports the
 * module, drives the exported entrypoint with the marker planted in several plausible input shapes
 * (row arrays, object rows, a bare value), and reports the first output cell that begins with a
 * formula char and carries the marker. A neutralized cell (`'=…` or a leading tab) begins with `'` /
 * `\t`, not `= + - @`, so it does NOT fire — no false positive on a correctly-escaped serializer.
 */
function csvProbeDriver(moduleRel: string, fnName: string, marker: string): string {
  const mod = JSON.stringify("./" + moduleRel);
  const fn = JSON.stringify(fnName);
  const mk = JSON.stringify(marker);
  return `
const MARKER = ${mk};
const F = "=" + MARKER;              // the benign formula payload
const inputs = [ [[F, F]], [{ a: F, b: F, c: F }], [F], { a: F, b: F }, F ];
let m;
try { m = await import(${mod}); } catch (e) { process.stdout.write("IMPORT_FAIL:" + e); process.exit(0); }
const fn = (m && m[${fn}]) || (m && m.default && (m.default[${fn}] || m.default));
if (typeof fn !== "function") { process.stdout.write("NOT_A_FUNCTION"); process.exit(0); }
let fired = null;
for (const input of inputs) {
  let out;
  try { out = await fn(input); } catch (e) { continue; }
  const s = typeof out === "string" ? out : (out && out.stdout ? String(out.stdout) : String(out == null ? "" : out));
  for (const line of s.split(/\\r?\\n/)) {
    for (let cell of line.split(",")) {
      cell = cell.replace(/^"|"$/g, "");                  // strip RFC-4180 quoting to see the real first char
      if (/^[=+@\\-]/.test(cell) && cell.indexOf(MARKER) !== -1) { fired = cell.slice(0, 90); break; }
    }
    if (fired) break;
  }
  if (fired) break;
}
process.stdout.write(fired ? ("CSVI_FIRED cell=" + fired) : "no-csvi");
`.trim();
}

export class CsvInjectionAttacker implements Attacker {
  readonly attackClass = "csv-injection" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "csv-injection-node");

  handles(file: string): boolean {
    return NODE_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
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
      if (!SINK_RE.test(source)) continue; // no CSV-serialization lead
      const names = nodeExportedNames(source);
      if (names.length === 0) continue;
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "csv-serialize").trim().slice(0, 24);

      let fired = false;
      for (const name of names) {
        if (fired) break;
        const marker = freshMarker();
        const driverRel = `.raeuber-driver-${marker}.mjs`;
        sandbox.writeFile(driverRel, csvProbeDriver(file, name, marker));
        const run = sandbox.exec(`${NODE_RUN} ${driverRel} 2>&1`, 15_000);
        const out = run.stdout + run.stderr;
        if (out.includes("CSVI_FIRED") && out.includes(marker)) {
          exploits.push({
            attackClass: "csv-injection",
            proof: "formula-unescaped",
            file,
            line: sinkLine,
            sink,
            summary: `Exported \`${name}()\` serialises an untrusted value into CSV/spreadsheet output without neutralising a leading formula trigger (\`= + - @\`); the injected \`=${marker}\` survived as a live formula cell (executes in Excel/Sheets on open).`,
            payload: `=${marker}`,
            evidence:
              `driver drove ${name}() with a "=${marker}" cell; the produced output contained an ` +
              `un-neutralised formula cell:\n` +
              out.slice(0, 800),
          });
          fired = true;
        }
      }
    }
    return exploits;
  }
}
