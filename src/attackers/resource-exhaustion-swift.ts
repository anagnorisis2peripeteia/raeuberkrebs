import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, freshMarker } from "./attacker.js";
import { SWIFT_SOURCE_RE } from "./swift.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// Resource exhaustion / ReDoS (CWE-1333 / CWE-400) in Swift: untrusted input reaches an
// `NSRegularExpression` / `Regex` whose pattern backtracks catastrophically. Unlike the injection
// lanes there is no "guard" to miss — the vuln is intrinsic to the regex. Swift app entrypoints won't
// compile in isolation (they import CodexBarCore/AppKit), so instead of driving the entrypoint this
// lane EXTRACTS the pattern from the source and times the compiled regex directly against crafted
// inputs — a self-contained proof that needs no app build. The find is a catastrophic-shaped pattern;
// the proof is a FIRED hang (a short crafted input blows the time budget while a benign input is
// instant). Reachability — that untrusted input reaches the regex — is the reach-the-sink triage.

// A Swift regex sink: NSRegularExpression / Regex / a `.regularExpression`-option string match.
const SINK_RE = /\bNSRegularExpression\s*\(|\btry\s+Regex\s*\(|options:\s*(?:\[[^\]]*)?\.regularExpression/;

// A catastrophic-backtracking group: quantified AND whose content is itself quantified or an
// alternation — `(a+)+`, `(\w+)*`, `(?:\\.|[^'])*`, `(a|ab)+`. (Shared shape with the Node lane.)
const CATASTROPHIC_SHAPE = /\((?:\?:)?(?:[^()]*[+*][^()]*|[^()|]*\|[^()]*)\)\s*[*+]/;

/** Swift raw-string literals (`#"…"#`) in the source — where regex patterns almost always live (raw
 *  strings avoid escaping). Returns each literal's inner text with its 1-indexed line. */
function rawStringLiterals(source: string): Array<{ pattern: string; line: number }> {
  const out: Array<{ pattern: string; line: number }> = [];
  // `#"` … `"#` — content is any run not containing the closing `"#`.
  const re = /#"((?:[^"]|"(?!#))*)"#/g;
  for (const m of source.matchAll(re)) {
    const line = source.slice(0, m.index ?? 0).split("\n").length;
    out.push({ pattern: m[1], line });
  }
  return out;
}

/**
 * The Swift ReDoS lane. Extracts every catastrophic-shaped raw-string pattern in a file that uses a
 * regex sink, then compiles each in an isolated Swift driver and times it against a battery of
 * crafted inputs (common regex-reaching prefixes × pumpable trigger chars × ascending lengths). A
 * benign match must be instant; the fire is a short crafted input crossing the time threshold — a
 * single-input ReDoS. Its canary is a planted catastrophic-regex Swift fixture. Runs on the macOS host.
 */
export class ResourceExhaustionSwiftAttacker implements Attacker {
  readonly attackClass = "resource-exhaustion" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "resource-exhaustion-swift");
  private static readonly BUDGET_MS = 8000;

  handles(file: string): boolean {
    return SWIFT_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    if (!SINK_RE.test(source)) return [];
    return rawStringLiterals(source)
      .filter((l) => CATASTROPHIC_SHAPE.test(l.pattern))
      .map((l) => ({ line: l.line, sink: "catastrophic-regex" }));
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
      if (!SINK_RE.test(source)) continue; // no regex sink in this file
      const catastrophic = rawStringLiterals(source).filter((l) => CATASTROPHIC_SHAPE.test(l.pattern));
      if (catastrophic.length === 0) continue;

      let fired = false;
      for (const lead of catastrophic) {
        if (fired) break;
        const marker = freshMarker();
        const dir = `.rk-swift-${marker}`;
        const bin = `${dir}/drv`;
        sandbox.exec(`mkdir -p ${dir}`, 10_000);
        // Pass the pattern via a file so no Swift-string escaping can corrupt it.
        sandbox.writeFile(`${dir}/pattern.txt`, lead.pattern);
        sandbox.writeFile(`${dir}/main.swift`, redosDriver);

        sandbox.exec(`swiftc -suppress-warnings ${dir}/main.swift -o ${bin} 2>&1`, 180_000);
        const check = sandbox.exec(`test -f ${bin} && echo RK_BIN_OK || echo RK_NO_BIN`, 10_000);
        if (!check.stdout.includes("RK_BIN_OK")) continue;

        const run = sandbox.exec(`./${bin} ${dir}/pattern.txt 2>&1`, ResourceExhaustionSwiftAttacker.BUDGET_MS);
        const out = run.stdout + run.stderr;
        const benignRan = out.includes("BENIGN_OK") && !out.includes("SLOW_BASELINE");
        const measured = out.includes("REDOS_FIRED");
        // Exponential jump: benign was fast, we entered a TRY, but the driver never COMPLETED (killed).
        const hung = run.timedOut && benignRan && out.includes("TRY ") && !out.includes("COMPLETED");
        if (!measured && !hung) continue;

        exploits.push({
          attackClass: "resource-exhaustion",
          proof: "input-caused-hang",
          file,
          line: lead.line,
          sink: "catastrophic-regex",
          summary: `A regex in this file backtracks catastrophically; a short crafted input drove ${
            measured ? "super-linear time past the threshold" : "the process into a hang (killed at the budget)"
          } while a benign input matched instantly — a single-input ReDoS (CWE-1333).`,
          payload: `pattern ${JSON.stringify(lead.pattern.slice(0, 60))}… fed "<prefix>" + one char × N`,
          evidence:
            `benign match returned fast; the crafted input ${
              measured ? "crossed the time threshold" : "hung past the sandbox budget"
            }:\n` + out.slice(0, 700),
        });
        fired = true;
      }
    }
    return exploits;
  }
}

// The timing driver: reads the pattern from argv[1], compiles it, checks a benign input is instant,
// then times a battery of {regex-reaching prefixes} × {pumpable chars} × {ascending lengths}. A linear
// regex stays sub-millisecond; a catastrophic one crosses the threshold within a few extra characters.
const redosDriver = String.raw`import Foundation

let path = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""
guard let pattern = try? String(contentsOfFile: path, encoding: .utf8) else { print("NO_PATTERN"); exit(0) }
guard let re = try? NSRegularExpression(pattern: pattern) else { print("BAD_PATTERN"); exit(0) }

func matchMs(_ s: String) -> Double {
    let r = NSRange(s.startIndex..<s.endIndex, in: s)
    let t0 = Date()
    _ = re.matches(in: s, options: [], range: r)
    return Date().timeIntervalSince(t0) * 1000.0
}

// A benign, normal-shaped input must be fast — otherwise the regex is always-slow, not input-driven.
let benign = matchMs("a normal short value")
print("BENIGN_OK ms=\(Int(benign))")
if benign > 250 { print("SLOW_BASELINE"); exit(0) }

let THRESHOLD_MS = 400.0
// prefixes reach a catastrophic sub-group buried behind a fixed skeleton (e.g. T3Chat's -H $' );
// pump chars are the usual ambiguity triggers (backslash overlaps \\. ; letters/space/digits).
let prefixes = ["", "$'", "'", "\"", "-H $'", "a", "(", "="]
let pumps = ["\\", "a", " ", "1", "x", "\t"]
for n in [24, 30, 36, 40] {
    for prefix in prefixes {
        for pump in pumps {
            let evil = prefix + String(repeating: pump, count: n)
            print("TRY len=\(evil.count)")
            if matchMs(evil) > THRESHOLD_MS {
                print("REDOS_FIRED len=\(evil.count) prefix=\(prefix.debugDescription) pump=\(pump.debugDescription)")
                exit(0)
            }
        }
    }
}
print("COMPLETED no-redos")
`;
