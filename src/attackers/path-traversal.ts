import { dirname, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import { type Sandbox, bundleForImport } from "../sandbox.js";
import { type Attacker, type StaticLead, nodeRunCommand, NODE_SOURCE_RE, freshMarker, nodeExportedNames, readHandledSources, scanSinkLeads } from "./attacker.js";
import { driveEntrypointDriver } from "./entrypoint-driver.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// A path-traversal sink: a filesystem read whose path is built from a variable (path.join/resolve
// with a var, a template, or concatenation) rather than a fixed literal. A lead, not a finding.
const SINK_RE =
  /\b(?:readFileSync|readFile|createReadStream)\s*\(\s*(?:path\.(?:join|resolve)\s*\([^;)]*,\s*[A-Za-z_$]|[A-Za-z_$][\w$]*\s*[,)]|`[^`]*\$\{|['"][^'"]*['"]\s*\+|[A-Za-z_$][\w$]*\s*\+)/;

const DECISION_MARKER_FILE = "raeuber-decoy.txt";
const CONTROL_MARKER_FILE = "boundary-safe.txt";

// Traversal payloads targeting a decoy the app must NOT be able to reach. Two distinct escape shapes:
//   - lexical `../` out of a subdir base (the canary joins onto `public/`, so `../decoy` escapes to
//     the work-dir root where the in-root decoy sits);
//   - a capability bypass through the target's OWN `boundary-link` symlink (points to the work-dir's
//     parent), which defeats a naive resolve()+startsWith guard that a plain `../` cannot.
// Every target of these payloads is either the work-dir root or its parent — both OUTSIDE any
// boundary-respecting reader's intended directory, so a sound guard reaches NONE of them. (An earlier
// design also planted decoys in sub-dirs INSIDE the work dir; a guard confining reads to the whole
// work dir then read those as in-bounds and false-fired — those in-tree decoys are gone.)
function traversalPayloads(): string[] {
  return [
    `../${DECISION_MARKER_FILE}`,
    `../../${DECISION_MARKER_FILE}`,
    `../../../${DECISION_MARKER_FILE}`,
    `boundary-link/${DECISION_MARKER_FILE}`,
    `boundary-link/../${DECISION_MARKER_FILE}`,
  ];
}

// Plants the decoys + control markers and returns the boundary "root" label used only in evidence.
function setupBoundaryWorkspace(sandbox: Sandbox, secret: string, safeProbeMarker: string): string {
  const boundaryId = freshMarker().toLowerCase().replace(/_/g, "");
  const root = `.raeuber-boundary-${boundaryId}`;
  sandbox.exec("mkdir -p public", 10_000);

  // In-root decoy: the escape target for a SUBDIR-based reader (`public/` + `../` -> work-dir/decoy).
  // Its CONTENT is a fresh marker distinct from the filename, so an app that merely echoes the
  // requested PATH cannot false-positive — only an actual read of the file exfiltrates the content.
  sandbox.writeFile(DECISION_MARKER_FILE, secret);
  // In-bounds control markers: a boundary-respecting read returns THESE, never the secret.
  sandbox.writeFile(CONTROL_MARKER_FILE, safeProbeMarker);
  sandbox.writeFile(`public/${CONTROL_MARKER_FILE}`, safeProbeMarker);
  // Parent decoy: the escape target for a SYMLINK-capability bypass (a `boundary-link` -> work-dir
  // parent). Truly outside the work dir, so reaching it proves a real boundary escape — not an
  // in-bounds read.
  try {
    sandbox.writeFile(`../${DECISION_MARKER_FILE}`, secret);
  } catch {
    // parent writes may be blocked in a restricted sandbox — the in-root escape target still covers
    // the primary canary; only the symlink-capability boundary case needs the parent decoy.
  }

  return root;
}

function firstSinkLine(source: string): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) if (SINK_RE.test(lines[i])) return i + 1;
  return 1;
}

export class PathTraversalAttacker implements Attacker {
  readonly attackClass = "path-traversal" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "path-traversal-node");

  handles(file: string): boolean {
    return NODE_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    return scanSinkLeads(source, SINK_RE);
  }

  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
    const exploits: Exploit[] = [];
    const secret = freshMarker() + "_TRAVERSAL_SECRET";
    const controlMarker = freshMarker() + "_TRAVERSAL_CONTROL";
    const boundaryRoot = setupBoundaryWorkspace(sandbox, secret, controlMarker);
    const payloads = traversalPayloads();

    for (const { file, source } of readHandledSources(targetDir, files, (f) => this.handles(f))) {
      if (!SINK_RE.test(source)) continue;
      const names = nodeExportedNames(source);
      if (names.length === 0) continue;
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "readFileSync").split("(")[0].trim();
      const importRel = bundleForImport(sandbox, file) ?? file;

      let fired = false;
      for (const name of names) {
        if (fired) break;
        // Drive ONE payload at a time (each still shape-enumerated across function/class-method/
        // config-object + callback + settle), so we attribute the exact payload that read the outside
        // decoy. Fired = the OUTSIDE decoy's content came back in the captured output — a
        // boundary-respecting read only ever returns the in-bounds control marker, never the secret.
        for (const payload of payloads) {
          const driverRel = `.raeuber-pt-${freshMarker()}.mjs`;
          sandbox.writeFile(driverRel, driveEntrypointDriver(importRel, name, [payload]));
          const run = sandbox.exec(`${nodeRunCommand(targetDir)} ${driverRel} 2>&1`, 20_000);
          const out = run.stdout + run.stderr;
          if (!out.includes(secret)) continue;
          exploits.push({
            attackClass: "path-traversal",
            proof: "secret-exfiltrated",
            file,
            line: sinkLine,
            sink,
            summary:
              `Untrusted input to exported \`${name}()\` reaches a filesystem read with no containment; ` +
              `a traversal payload read a decoy planted outside the intended directory (including via ` +
              `async/callback, class-method, and config-object entrypoints).`,
            payload,
            evidence:
              `boundary topology => root=${boundaryRoot}; derived preview: appBase/${payload}; ` +
              `normalized: ${normalize(payload)}; the planted decoy secret (content marker ${secret}) ` +
              `was read back:\n` +
              out.slice(0, 600),
          });
          fired = true;
          break;
        }
      }
    }
    return exploits;
  }
}
