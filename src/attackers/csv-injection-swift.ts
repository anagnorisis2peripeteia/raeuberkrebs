import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, freshMarker, scanSinkLeads } from "./attacker.js";
import { SWIFT_SOURCE_RE, swiftDrivableFunctions, swiftDriverMain } from "./swift.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// A CSV/spreadsheet-serialization sink in Swift: a hand-rolled comma join, a write to a `.csv` file,
// or a `csvCell`/`csvRow`-style helper. A lead, not a finding — whether an untrusted cell survives
// WITHOUT formula-prefix neutralization is what the PoC decides. (Modelled on openclaw's google-meet
// `csvCell`, which quote-escapes but doesn't guard a leading `= + - @`.)
const SINK_RE =
  /\.joined\s*\(\s*separator:\s*["'],["']\s*\)|\.map\s*\{[^}]*\}\s*\.joined\s*\(\s*separator:\s*","|\bcsv[A-Za-z]*\s*\(|write\([^)]*\.csv|\.csv"/i;

/** A cell that still begins with a spreadsheet formula trigger (`= + - @`) after RFC-4180 quote
 *  stripping and carries the marker — un-neutralized. A `'=…`/tab-prefixed cell begins with `'`/`\t`,
 *  so a correctly-escaped serializer does not fire. */
function firstUnescapedFormulaCell(output: string, marker: string): string | null {
  for (const line of output.split(/\r?\n/)) {
    for (let cell of line.split(",")) {
      cell = cell.replace(/^"|"$/g, "");
      if (/^[=+@-]/.test(cell) && cell.includes(marker)) return cell.slice(0, 90);
    }
  }
  return null;
}

function shq(s: string): string {
  return "'" + s.replace(/'/g, `'\\''`) + "'";
}

function firstSinkLine(source: string): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) if (SINK_RE.test(lines[i])) return i + 1;
  return 1;
}

/**
 * The Swift CSV/formula-injection lane. CSV injection is unusual: the payload fires in the VICTIM's
 * spreadsheet, not our sandbox — so the proof is that a benign formula marker `=RAEUBER_<m>` SURVIVES
 * into the produced output as a cell that STILL begins with a formula trigger (`= + - @`),
 * un-neutralized (`formula-unescaped`). Drives a compiled Swift entrypoint (its first `String` arg =
 * the cell value) built with the shared `main.swift` driver, planting the formula marker; a
 * correctly-escaped serializer (`'`-prefix or tab) produces a cell beginning with `'`/`\t`, so it does
 * NOT fire. A file needing the rest of its package won't build in isolation (an honest miss). Runs on
 * the macOS host.
 */
export class CsvInjectionSwiftAttacker implements Attacker {
  readonly attackClass = "csv-injection" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "csv-injection-swift");

  handles(file: string): boolean {
    return SWIFT_SOURCE_RE.test(file);
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
      if (!SINK_RE.test(source)) continue; // no CSV-serialization sink
      const fns = swiftDrivableFunctions(source);
      if (fns.length === 0) continue;
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "csv-serialize").replace(/\s*\($/, "").trim();

      let fired = false;
      for (const fn of fns) {
        if (fired) break;
        const marker = freshMarker();
        const dir = `.rk-swift-${marker}`;
        const bin = `${dir}/drv`;
        sandbox.exec(`mkdir -p ${dir}`, 10_000);
        sandbox.writeFile(`${dir}/Target.swift`, source);
        sandbox.writeFile(`${dir}/main.swift`, swiftDriverMain(fn));
        sandbox.exec(`swiftc -suppress-warnings ${dir}/Target.swift ${dir}/main.swift -o ${bin} 2>&1`, 180_000);
        const check = sandbox.exec(`test -f ${bin} && echo RK_BIN_OK || echo RK_NO_BIN`, 10_000);
        if (!check.stdout.includes("RK_BIN_OK")) continue;

        // Drive with a benign formula payload; fire if it survives into the output un-neutralized.
        const payload = `=${marker}`;
        const run = sandbox.exec(`./${bin} ${shq(payload)} 2>&1`, 30_000);
        const cell = firstUnescapedFormulaCell(run.stdout ?? "", marker);
        if (cell) {
          const receiver = fn.enclosingType ? `${fn.enclosingType}.${fn.name}` : fn.name;
          exploits.push({
            attackClass: "csv-injection",
            proof: "formula-unescaped",
            file,
            line: sinkLine,
            sink,
            summary: `Untrusted first argument of \`${receiver}()\` reaches a CSV serializer with no formula-prefix neutralization; a \`=…\` cell survived into the output and would execute in a spreadsheet.`,
            payload,
            evidence: `drove ${receiver}(${JSON.stringify(payload)}); the produced output carried an un-neutralized formula cell: ${JSON.stringify(cell)}`,
          });
          fired = true;
        }
      }
    }
    return exploits;
  }
}
