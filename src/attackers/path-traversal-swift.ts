import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, freshMarker, scanSinkLeads } from "./attacker.js";
import { SWIFT_SOURCE_RE, swiftDrivableFunctions, swiftDriverMain } from "./swift.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// A path-traversal sink in Swift: a filesystem read (`String(contentsOfFile:)`, `Data(contentsOf:)`,
// `NSString(contentsOfFile:)`, `FileHandle(forReadingAtPath:)`, `FileManager.contents(atPath:)`).
// A lead, not a finding — whether the path is attacker-influenced is what the PoC decides.
const SINK_RE =
  /\bString\s*\(\s*contentsOf(?:File)?:|\bData\s*\(\s*contentsOf:|\bNSString\s*\(\s*contentsOfFile:|\bNSData\s*\(\s*contentsOfFile:|\bFileHandle\s*\(\s*forReadingAtPath:|\.contents\s*\(\s*atPath:/;

// The read path is built from a variable — `appendingPathComponent(var)`, a `+` concatenation, or a
// `\(…)` interpolation — rather than a fixed literal. A read of a constant path can't traverse.
const TAINT_RE =
  /appendingPathComponent\s*\(\s*[A-Za-z_]|\\\(|["'][^"'\n]*["']\s*\+\s*[A-Za-z_]|[A-Za-z_]\w*\s*\+\s*["']/;

// Traversal payloads of increasing depth, plus the no-traversal case. The decoy is planted at the
// sandbox root; one of these reaches it from the app's base dir (which the fixture roots at ./public).
const PAYLOADS = [
  "../raeuber-decoy.txt",
  "../../raeuber-decoy.txt",
  "../../../raeuber-decoy.txt",
  "raeuber-decoy.txt",
];

function shq(s: string): string {
  return "'" + s.replace(/'/g, `'\\''`) + "'";
}

function firstSinkLine(source: string): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) if (SINK_RE.test(lines[i])) return i + 1;
  return 1;
}

/**
 * The Swift path-traversal lane. Proof is `secret-exfiltrated` (mirrors the Node lane): plant a decoy
 * file at the sandbox root whose CONTENT is a fresh marker distinct from its filename, then drive `../`
 * payloads through a compiled Swift entrypoint. An app that merely echoes the requested PATH cannot
 * false-positive — only an actual read of the file exfiltrates the content marker. Compiles the
 * changed file with a generated `main.swift` driver (via `swift.ts`) and runs it once per payload; a
 * file needing the rest of its package won't build in isolation (an honest miss). Runs on the macOS
 * host (local sandbox).
 */
export class PathTraversalSwiftAttacker implements Attacker {
  readonly attackClass = "path-traversal" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "path-traversal-swift");

  handles(file: string): boolean {
    return SWIFT_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    if (!TAINT_RE.test(source)) return []; // read of a constant path → can't traverse
    return scanSinkLeads(source, SINK_RE);
  }

  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
    const exploits: Exploit[] = [];
    // Plant a decoy secret at the sandbox root. Its CONTENT is a fresh marker distinct from its
    // filename, so an app that only echoes back the requested path cannot false-positive.
    const secret = freshMarker() + "_TRAVERSAL_SECRET";
    sandbox.writeFile("raeuber-decoy.txt", secret);

    for (const file of files) {
      if (!this.handles(file)) continue;
      let source: string;
      try {
        source = readFileSync(join(targetDir, file), "utf8");
      } catch {
        continue;
      }
      if (!SINK_RE.test(source)) continue; // no file-read sink
      if (!TAINT_RE.test(source)) continue; // path is a constant literal — not traversable
      const fns = swiftDrivableFunctions(source);
      if (fns.length === 0) continue;
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "String(contentsOfFile:").replace(/\s*\($/, "").trim();

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

        for (const payload of PAYLOADS) {
          const run = sandbox.exec(`./${bin} ${shq(payload)} 2>&1`, 30_000);
          const out = run.stdout + run.stderr;
          // Fired = the decoy's CONTENT marker (never its filename) came back — an actual read of the
          // out-of-base file, not a path echo.
          if (out.includes(secret)) {
            const receiver = fn.enclosingType ? `${fn.enclosingType}.${fn.name}` : fn.name;
            exploits.push({
              attackClass: "path-traversal",
              proof: "secret-exfiltrated",
              file,
              line: sinkLine,
              sink,
              summary: `Untrusted first argument of \`${receiver}()\` reaches a file-read path with no containment; a \`../\` payload read a planted out-of-base decoy.`,
              payload,
              evidence:
                `driver invoked ${receiver}(${JSON.stringify(payload)}); the planted decoy's content ` +
                `marker ${secret} was returned — the read escaped its base directory:\n` +
                out.slice(0, 800),
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
