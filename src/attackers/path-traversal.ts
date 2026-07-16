import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, freshMarker, nodeExportedNames, nodeRequireDriver, scanSinkLeads } from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// A path-traversal sink: a filesystem read whose path is built from a variable (path.join/resolve
// with a var, a template, or concatenation) rather than a fixed literal. A lead, not a finding.
const SINK_RE =
  /\b(?:readFileSync|readFile|createReadStream)\s*\(\s*(?:path\.(?:join|resolve)\s*\([^;)]*,\s*[A-Za-z_$]|`[^`]*\$\{|['"][^'"]*['"]\s*\+|[A-Za-z_$][\w$]*\s*\+)/;

// Traversal payloads of increasing depth, plus the no-traversal case (app reads from cwd). The
// decoy is planted at the sandbox root; one of these reaches it from the app's base dir.
const PAYLOADS = ["../raeuber-decoy.txt", "../../raeuber-decoy.txt", "../../../raeuber-decoy.txt", "raeuber-decoy.txt"];

function firstSinkLine(source: string): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) if (SINK_RE.test(lines[i])) return i + 1;
  return 1;
}

export class PathTraversalAttacker implements Attacker {
  readonly attackClass = "path-traversal" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "path-traversal-node");

  handles(file: string): boolean {
    return /\.(?:js|cjs)$/.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    return scanSinkLeads(source, SINK_RE);
  }

  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
    const exploits: Exploit[] = [];
    // Plant a decoy secret at the sandbox root. Its CONTENT is a fresh marker distinct from its
    // filename, so an app that merely echoes back the requested PATH cannot false-positive — only an
    // actual read of the file exfiltrates the content marker.
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
      if (!SINK_RE.test(source)) continue;
      const names = nodeExportedNames(source);
      if (names.length === 0) continue;
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "readFileSync").split("(")[0].trim();

      let fired = false;
      for (const name of names) {
        if (fired) break;
        for (const payload of PAYLOADS) {
          const driverRel = `.raeuber-driver-${freshMarker()}.cjs`;
          sandbox.writeFile(driverRel, nodeRequireDriver(file, name, payload));
          const run = sandbox.exec(`node ${driverRel} 2>&1`, 15_000);
          const out = run.stdout + run.stderr;
          if (out.includes(secret)) {
            exploits.push({
              attackClass: "path-traversal",
              proof: "secret-exfiltrated",
              file,
              line: sinkLine,
              sink,
              summary: `Untrusted first argument of exported \`${name}()\` reaches a filesystem read with no containment; a \`../\` payload read a file outside the intended directory.`,
              payload,
              evidence:
                `driver called ${name}(${JSON.stringify(payload)}); the planted decoy secret ` +
                `(content marker ${secret}) was read back out via traversal:\n` +
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
