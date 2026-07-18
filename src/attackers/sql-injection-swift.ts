import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, freshMarker, scanSinkLeads } from "./attacker.js";
import { SWIFT_SOURCE_RE, swiftDrivableFunctions, swiftDriverMain } from "./swift.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// A SQL-injection sink in Swift: a query executed via the SQLite C API (`sqlite3_prepare*`,
// `sqlite3_exec`) or a GRDB raw-SQL execution. A lead, not a finding.
const SINK_RE =
  /\bsqlite3_prepare(?:_v2|_v3)?\s*\(|\bsqlite3_exec\s*\(|\.(?:execute|fetchAll|fetchOne|fetchCursor)\s*\(\s*sql:|\btry\s+\w+\.(?:execute|makeStatement)\s*\(/;

// The query is built from a variable — a Swift string interpolation `\(…)` or a `+` concatenation —
// rather than a fully parameterized statement. A constant/parameterized query can't inject.
const TAINT_RE = /\\\(|["'][^"'\n]*["']\s*\+\s*[A-Za-z_]|[A-Za-z_]\w*\s*\+\s*["']/;

// A benign value unlikely to match any row, and injection payloads that bypass the WHERE clause via
// single- and double-quote breakouts. If the injection returns data the benign input does not, the
// query's WHERE was bypassed — the interpolation is injectable.
const BENIGN = "zzz_raeuber_nomatch_9d1";
function injections(): string[] {
  return [
    `zzz' OR '1'='1`,
    `zzz' OR 1=1 -- `,
    `zzz" OR "1"="1`,
    `zzz') OR ('1'='1`,
  ];
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
 * The Swift SQL-injection lane. Same cardinal rule as the family — a finding is a payload that
 * actually changed the query's result — proven differentially: a benign no-match input returns
 * nothing, while an `' OR '1'='1`-style payload bypasses the `WHERE` and returns rows it should not
 * (`secret-exfiltrated`). Drives a compiled Swift entrypoint built with the shared `main.swift`
 * driver; a file needing the rest of its package won't build in isolation (an honest miss). Runs on
 * the macOS host.
 */
export class SqlInjectionSwiftAttacker implements Attacker {
  readonly attackClass = "sql-injection" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "sql-injection-swift");

  handles(file: string): boolean {
    return SWIFT_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    if (!TAINT_RE.test(source)) return []; // parameterized / constant query → not injectable
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
      if (!SINK_RE.test(source)) continue; // no SQL sink
      if (!TAINT_RE.test(source)) continue; // query is constant/parameterized — not injectable
      const fns = swiftDrivableFunctions(source);
      if (fns.length === 0) continue;
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "sqlite3_prepare").replace(/\s*\($/, "").trim();

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

        const benign = (sandbox.exec(`./${bin} ${shq(BENIGN)} 2>&1`, 30_000).stdout ?? "").trim();
        for (const payload of injections()) {
          const inj = (sandbox.exec(`./${bin} ${shq(payload)} 2>&1`, 30_000).stdout ?? "").trim();
          // Fired = the injection returned data the benign no-match input did not — the WHERE clause
          // was bypassed. A parameterized query treats the payload as a literal (still no match), so
          // benign == injection == empty → no false positive.
          const extra = inj !== benign && inj.length > benign.length && inj.replace(benign, "").trim().length > 0;
          if (extra) {
            const receiver = fn.enclosingType ? `${fn.enclosingType}.${fn.name}` : fn.name;
            exploits.push({
              attackClass: "sql-injection",
              proof: "secret-exfiltrated",
              file,
              line: sinkLine,
              sink,
              summary: `Untrusted first argument of \`${receiver}()\` is interpolated into a SQL query; an \`OR '1'='1\`-style payload bypassed the WHERE clause and returned rows a benign input did not.`,
              payload,
              evidence:
                `benign input ${JSON.stringify(BENIGN)} returned ${JSON.stringify(benign.slice(0, 120))}; ` +
                `injection ${JSON.stringify(payload)} returned extra rows: ${JSON.stringify(inj.slice(0, 200))}`,
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
