import { readFileSync } from "node:fs";
import { dirname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, nodeRunCommand, NODE_SOURCE_RE, freshMarker, nodeExportedNames, nodeImportDriver, scanSinkLeads } from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// A path-traversal sink: a filesystem read whose path is built from a variable (path.join/resolve
// with a var, a template, or concatenation) rather than a fixed literal. A lead, not a finding.
const SINK_RE =
  /\b(?:readFileSync|readFile|createReadStream)\s*\(\s*(?:path\.(?:join|resolve)\s*\([^;)]*,\s*[A-Za-z_$]|`[^`]*\$\{|['"][^'"]*['"]\s*\+|[A-Za-z_$][\w$]*\s*\+)/;

const DECISION_MARKER_FILE = "raeuber-decoy.txt";
const CONTROL_MARKER_FILE = "boundary-safe.txt";

interface DifferentialPayload {
  label: string;
  input: string;
}

interface BoundaryTopology {
  root: string;
  workspace: string;
  sibling: string;
  bridge: string;
  safeProbeInputs: string[];
  differentialInputs: DifferentialPayload[];
}

// Legacy traversal payloads kept for backwards coverage where the simple "../" path still bypasses.
const LEGACY_PAYLOADS = ["../raeuber-decoy.txt", "../../raeuber-decoy.txt", "../../../raeuber-decoy.txt"];

function setupBoundaryWorkspace(
  sandbox: Sandbox,
  secret: string,
  safeProbeMarker: string,
): BoundaryTopology {
  const boundaryId = freshMarker().toLowerCase().replace(/_/g, "");
  const root = `.raeuber-boundary-${boundaryId}`;
  const workspace = `${root}/workspace`;
  const outside = `${root}/outside`;
  const sibling = `${root}-sibling`;
  const bridge = `${root}-bridge`;
  const safeInWorkspace = `${workspace}/${CONTROL_MARKER_FILE}`;

  sandbox.exec(`mkdir -p ${root}/workspace ${root}/outside public ${sibling} ${bridge}`, 10_000);

  // Canonical canary: a root read remains available for the pre-existing lane behavior.
  sandbox.writeFile(DECISION_MARKER_FILE, secret);

  // Differential control marker and decoys.
  sandbox.writeFile("boundary-safe.txt", safeProbeMarker);
  sandbox.writeFile(safeInWorkspace, safeProbeMarker);
  sandbox.writeFile(`public/${CONTROL_MARKER_FILE}`, safeProbeMarker);
  sandbox.writeFile(`${outside}/${DECISION_MARKER_FILE}`, secret);
  sandbox.writeFile(`${sibling}/${DECISION_MARKER_FILE}`, secret);
  sandbox.writeFile(`${bridge}/${DECISION_MARKER_FILE}`, secret);

  // Symlink + dangling path variants. The candidate list then includes bridge, sibling, and mount-like
  // forms over exactly the same seeded topology.
  sandbox.exec(`ln -sf ../outside ${workspace}/bridge-link`, 10_000);
  sandbox.exec(`ln -sf ../outside ${workspace}/bridge-mount`, 10_000);
  sandbox.exec(`ln -sf ../missing-target ${workspace}/dangling-link`, 10_000);

  return {
    root,
    workspace,
    sibling,
    bridge,
    safeProbeInputs: [
      "boundary-safe.txt",
      `public/${CONTROL_MARKER_FILE}`,
      safeInWorkspace,
      `../${safeInWorkspace}`,
      `../public/${CONTROL_MARKER_FILE}`,
    ],
    differentialInputs: [
      { label: "dotdot-tail", input: `../${DECISION_MARKER_FILE}` },
      { label: "dotdot-tail-deep", input: `../../${DECISION_MARKER_FILE}` },
      { label: "sibling-root", input: `../${sibling}/${DECISION_MARKER_FILE}` },
      { label: "bridge-mount", input: `../${bridge}/${DECISION_MARKER_FILE}` },
      { label: "alias-boundary-link", input: `${workspace}/bridge-link/${DECISION_MARKER_FILE}` },
      { label: "alias-boundary-mount", input: `${workspace}/bridge-mount/${DECISION_MARKER_FILE}` },
      { label: "symlink-tail", input: `${workspace}/bridge-link/../${DECISION_MARKER_FILE}` },
      { label: "dangling-symlink", input: `${workspace}/dangling-link/${DECISION_MARKER_FILE}` },
      { label: "legacy-alias", input: `boundary-link/${DECISION_MARKER_FILE}` },
      { label: "outside-directory", input: `${outside}/${DECISION_MARKER_FILE}` },
    ],
  };
}

function firstSuccessfulSafeProbe(
  sandbox: Sandbox,
  file: string,
  targetDir: string,
  safeInputs: string[],
  names: string[],
  baselineMarker: string,
  safeInfo: { [key: string]: string },
): { input: string; output: string } | null {
  for (const input of safeInputs) {
    for (const name of names) {
      const driverRel = `.raeuber-driver-${freshMarker()}.mjs`;
      sandbox.writeFile(driverRel, nodeImportDriver(file, name, input));
      const run = sandbox.exec(`${nodeRunCommand(targetDir)} ${driverRel} 2>&1`, 15_000);
      const out = run.stdout + run.stderr;
      if (out.includes(baselineMarker)) {
        safeInfo.reason = `control probe ${input} on ${name}`;
        return { input, output: out };
      }
    }
  }
  safeInfo.reason = "no safe-marker control probe read back";
  return null;
}

function runProbe(
  sandbox: Sandbox,
  file: string,
  fnName: string,
  targetDir: string,
  payload: string,
): string {
  const driverRel = `.raeuber-driver-${freshMarker()}.mjs`;
  sandbox.writeFile(driverRel, nodeImportDriver(file, fnName, payload));
  const run = sandbox.exec(`${nodeRunCommand(targetDir)} ${driverRel} 2>&1`, 15_000);
  return run.stdout + run.stderr;
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
    // Plant a decoy secret at the sandbox root. Its CONTENT is a fresh marker distinct from its
    // filename, so an app that merely echoes back the requested PATH cannot false-positive — only an
    // actual read of the file exfiltrates the content marker.
    const secret = freshMarker() + "_TRAVERSAL_SECRET";
    const controlMarker = freshMarker() + "_TRAVERSAL_CONTROL";
    const topology = setupBoundaryWorkspace(sandbox, secret, controlMarker);

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
      const safeProbeInfo: { [key: string]: string } = {};
        const hasInRootControl = Boolean(
          firstSuccessfulSafeProbe(sandbox, file, targetDir, topology.safeProbeInputs, names, controlMarker, safeProbeInfo),
        );

      let fired = false;
      for (const name of names) {
        if (fired) break;
        if (hasInRootControl) {
          for (const p of topology.differentialInputs) {
            const output = runProbe(sandbox, file, name, targetDir, p.input);
            if (output.includes(secret)) {
              exploits.push({
                attackClass: "path-traversal",
                proof: "secret-exfiltrated",
                file,
                line: sinkLine,
                sink,
                summary: `Untrusted input on \`${name}()\` bypasses a filesystem-capability boundary (` +
                  `${p.label}) by reaching a marker outside the intended workspace while control probe` +
                  " control remained within it.",
                payload: p.input,
                evidence:
                  `control probe: ${safeProbeInfo.reason}; boundary topology => root=${topology.root}, ` +
                  `sibling=${topology.sibling}, bridge=${topology.bridge};\n` +
                  `raw boundary input: ${JSON.stringify(p.input)}; normalized: ` +
                  `${normalize(p.input)}; derived preview: appBase/${p.input};\n` +
                  output.slice(0, 800),
              });
              fired = true;
              break;
            }
          }
        }

        if (fired) break;
        for (const legacyPayload of LEGACY_PAYLOADS) {
          const out = runProbe(sandbox, file, name, targetDir, legacyPayload);
          if (out.includes(secret)) {
            exploits.push({
              attackClass: "path-traversal",
              proof: "secret-exfiltrated",
              file,
              line: sinkLine,
              sink,
              summary: `Untrusted first argument of exported \`${name}()\` reaches a filesystem read with` +
                " no containment; a `../` payload read a file outside the intended directory.",
              payload: legacyPayload,
              evidence:
                `driver called ${name}(${JSON.stringify(legacyPayload)}); the planted decoy secret ` +
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
