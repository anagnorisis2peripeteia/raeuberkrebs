import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import { type Sandbox, ensurePythonEnv } from "../sandbox.js";
import { type Attacker, type StaticLead, PYTHON_SOURCE_RE, freshMarker } from "./attacker.js";
import { PYTHON_SANDBOX_IMAGE, differentialOraclePythonDriver, shq } from "./python-driver.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// The command-approval differential oracle, Python edition. Instead of driving a payload through a
// code SINK, it probes a target's own command-safety DECISION function (an approval / allowlist gate)
// and diffs its BELIEF (the gate approves the command) against GROUND TRUTH (running the command
// fires the benign marker). A divergence — approved AND it executed injected code — is a proven
// bypass of the gate. It correctly does NOT fire on a sound gate that rejects shell metacharacters.

// A decision function is a `def name(arg, …)` whose name carries BOTH a decision verb AND a
// command/safety noun — e.g. `is_command_safe`, `validate_command`, `can_run`, `is_allowed`. Requiring
// both keeps generic predicates (`is_empty`, `validate_email`, `check_type`) out of the probe set.
const DEF_RE = /^def\s+([A-Za-z_]\w*)\s*\(\s*[A-Za-z_]\w*(?:\s*,[^)]*)?\)\s*:/gm;
const DECISION_VERB_RE = /(?:is|are|can|should|allow|approv|permit|authoriz|valid|check|sanitiz|verif|guard|trust|whitelist|screen|vet)/i;
const CMD_SAFETY_RE = /(?:safe|command|cmd|exec|shell|run|allow|danger|block|trust|permit|whitelist|input|payload|script)/i;

// Adversarial corpus: a plausibly-safe-looking prefix carrying an INJECTED marker via a shell
// metacharacter. A gate that approves any of these has approved shell injection. `{{MARK}}` is
// replaced per-run by a fresh unguessable marker; the substituted string is both judged and run.
const CORPUS = [
  "ls; echo {{MARK}}",
  "ls && echo {{MARK}}",
  "ls || echo {{MARK}}",
  "echo hi | echo {{MARK}}",
  "ls $(echo {{MARK}})",
  "ls `echo {{MARK}}`",
  "cat /etc/hostname; echo {{MARK}}",
  "ls; echo {{MARK}} #",
];

function decisionFunctions(source: string): string[] {
  const names: string[] = [];
  for (const m of source.matchAll(DEF_RE)) {
    const name = m[1];
    if (DECISION_VERB_RE.test(name) && CMD_SAFETY_RE.test(name)) names.push(name);
  }
  return [...new Set(names)];
}

function firstDecisionLine(source: string, names: Set<string>): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^def\s+([A-Za-z_]\w*)\s*\(/);
    if (m && names.has(m[1])) return i + 1;
  }
  return 1;
}

export class PolicyBeliefDivergencePythonAttacker implements Attacker {
  readonly attackClass = "policy-belief-divergence" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "differential-oracle-python");
  readonly sandboxImage = PYTHON_SANDBOX_IMAGE;

  handles(file: string): boolean {
    return PYTHON_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    const names = decisionFunctions(source);
    if (names.length === 0) return [];
    const lines = source.split("\n");
    const leads: StaticLead[] = [];
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(/^def\s+([A-Za-z_]\w*)\s*\(/);
      if (m && names.includes(m[1])) leads.push({ line: i + 1, sink: `belief:${m[1]}()` });
    }
    return leads;
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
      const names = decisionFunctions(source);
      if (names.length === 0) continue;
      const decisionLine = firstDecisionLine(source, new Set(names));

      const marker = freshMarker();
      const corpus = CORPUS.map((c) => c.split("{{MARK}}").join(marker));
      const driverRel = `.raeuber-oracle-${marker}.py`;
      sandbox.writeFile(driverRel, differentialOraclePythonDriver(file, names, marker, corpus));
      const out = sandbox.exec(`${py} ${shq(driverRel)} 2>&1`, 20_000);
      const output = out.stdout + out.stderr;
      for (const line of output.split("\n")) {
        const m = line.match(/^RK_DIVERGENCE fn=(\S+) (.+)$/);
        if (!m) continue;
        const fnName = m[1];
        let input: string;
        try {
          input = JSON.parse(m[2]);
        } catch {
          continue;
        }
        const key = `${file}::${fnName}::${input}`;
        if (seen.has(key)) continue;
        seen.add(key);
        exploits.push({
          attackClass: "policy-belief-divergence",
          proof: "belief-diverged",
          file,
          line: decisionLine,
          sink: `belief:${fnName}()`,
          summary:
            `The command-approval control \`${fnName}()\` judged \`${input}\` safe/allowed, but running ` +
            `it executed the benign marker — its belief diverges from actual behavior (its own gate is bypassed).`,
          payload: input,
          evidence:
            `belief=safe AND ground-truth fired the marker for ${fnName}(${JSON.stringify(input)}):\n` +
            output.slice(0, 400),
        });
      }
    }
    return exploits;
  }
}
