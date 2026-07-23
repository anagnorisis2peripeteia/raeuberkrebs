import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import { type Sandbox, ensurePythonEnv } from "../sandbox.js";
import { type Attacker, type StaticLead, PYTHON_SOURCE_RE, freshMarker } from "./attacker.js";
import { type AssignmentIndirectionItem, PYTHON_SANDBOX_IMAGE, assignmentIndirectionDriver, shq } from "./python-driver.js";
import { detectorFunctions, firstDetectorLine, detectorLeads } from "./command-guard-oracle.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// The assigned-variable command-name indirection corpus (issue #93). The shell-obfuscation corpus
// handles STATELESS command-word rewrites (`$(echo rm)`, `${0/x/r}m`, glob argv[0]); this lane models
// ASSIGNMENT STATE — a command that binds a variable earlier on the SAME line and expands it in command
// position (`CMD=rm; $CMD -rf /`, char-concat `a=r; b=m; $a$b`, brace `${X}`, absolute-path value). The
// shell resolves the variable at run time; a guard that resolves `$(…)`/`${…}` but not same-line
// `VAR=value` sees an unresolved `$CMD` and misses the dangerous command. Fires on the verdict flip
// (resolved `control` flagged, indirection `carrier` cleared) AND a runtime collapse proof: a benign
// marker-echo twin using the identical assignment mechanism echoes the marker. The runtime proof is why
// a naive `$VAR` over-block (`$PYTHON script.py`) is not modelled — only a same-line assignment that
// provably collapses fires.
const CONTROL = "rm -rf /";
const ITEMS: AssignmentIndirectionItem[] = [
  { control: CONTROL, carrier: "CMD=rm; $CMD -rf /", markerForm: "V=echo; $V {{MARK}}", technique: "simple-var" },
  { control: CONTROL, carrier: "X=rm; ${X} -rf /", markerForm: "V=echo; ${V} {{MARK}}", technique: "brace-var" },
  { control: CONTROL, carrier: "a=r; b=m; $a$b -rf /", markerForm: "a=ec; b=ho; $a$b {{MARK}}", technique: "char-concat" },
  { control: CONTROL, carrier: "X=/bin/rm; $X -rf /", markerForm: "V=/bin/echo; $V {{MARK}}", technique: "absolute-path-var" },
];

/**
 * Assigned-variable command-name indirection coverage-differential lane (Python guards). Fires when a
 * command-danger detector flags `rm -rf /` but clears its same-line-assignment indirection form
 * (`CMD=rm; $CMD -rf /`) AND bash proves the assignment mechanism resolves at runtime via a benign
 * marker twin — a real hardline-floor bypass the guard's stateless normalization misses (CWE-693).
 */
export class AssignmentIndirectionPythonAttacker implements Attacker {
  readonly attackClass = "policy-belief-divergence" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "assignment-indirection-python");
  readonly sandboxImage = PYTHON_SANDBOX_IMAGE;

  handles(file: string): boolean {
    return PYTHON_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    return detectorLeads(source);
  }

  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
    const exploits: Exploit[] = [];
    const py = ensurePythonEnv(sandbox, targetDir);
    const seen = new Set<string>();
    for (const file of files) {
      if (!this.handles(file)) continue;
      let source: string;
      try {
        source = readFileSync(join(targetDir, file), "utf8");
      } catch {
        continue;
      }
      const names = detectorFunctions(source);
      if (names.length === 0) continue;
      const detectorLine = firstDetectorLine(source, new Set(names));

      const marker = freshMarker();
      const driverRel = `.raeuber-assign-${marker}.py`;
      sandbox.writeFile(driverRel, assignmentIndirectionDriver(file, names, marker, ITEMS));
      const out = sandbox.exec(`${py} ${shq(driverRel)} 2>&1`, 30_000);
      const output = out.stdout + out.stderr;
      for (const line of output.split("\n")) {
        const m = line.match(/^RK_ASSIGN fn=(\S+) (.+)$/);
        if (!m) continue;
        const fnName = m[1];
        let item: { control: string; carrier: string; technique: string };
        try {
          item = JSON.parse(m[2] ?? "");
        } catch {
          continue;
        }
        const key = `${file}::${fnName}::${item.carrier}`;
        if (seen.has(key)) continue;
        seen.add(key);
        exploits.push({
          attackClass: "policy-belief-divergence",
          proof: "coverage-gap",
          file,
          line: detectorLine,
          sink: `detector:${fnName}()`,
          summary:
            `The danger detector \`${fnName}()\` flags \`${item.control}\` but CLEARS its same-line ` +
            `assignment-indirection form \`${item.carrier}\` (${item.technique}) — it never resolves the ` +
            `\`VAR=value\` binding, so the shell reconstructs the dangerous command at run time and it ` +
            `bypasses the guard (fail-open).`,
          payload: item.carrier,
          evidence:
            `${fnName}(${JSON.stringify(item.control)}) = flagged, ${fnName}(${JSON.stringify(item.carrier)}) = ` +
            `cleared, and a benign marker twin using the identical ${item.technique} assignment mechanism ` +
            `resolved at runtime (bash echoed the fresh marker ${marker}):\n` +
            output.slice(0, 400),
        });
      }
    }
    return exploits;
  }
}
