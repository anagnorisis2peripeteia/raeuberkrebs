// Differential-oracle primitive — the reusable machinery behind a "the security control believes
// this is safe, but it actually executes" finding. It generalizes the manual harnesses that found
// the openclaw exec-approval bypasses (command/builtin/exec carriers, wrapper-leaf tools,
// allow-always any-args reuse): instead of driving a payload through a code SINK, it probes a
// target's own security-DECISION function (approval / allowlist / policy) and diffs its BELIEF
// against GROUND TRUTH.
//
// For each adversarial input: if the control BELIEVES it safe/allowed AND running it fires the
// benign marker, that is a proven divergence — the control auto-approves something that actually
// runs. This still satisfies the family's "evidence or it didn't count" rule: the proof is a marker
// that executed while the control claimed the input was safe.
//
// A concrete oracle lane supplies only the target-specific pieces (which module holds the decision,
// a `beliefExpr` that calls its API, and an adversarial `corpus`); this file owns the driver
// generation, sandbox orchestration, divergence parsing, and Exploit construction. See PLAYBOOK.md
// for how to instantiate one on a new target.
import type { Attacker, StaticLead } from "./attackers/attacker.js";
import { nodeRunCommand, freshMarker } from "./attackers/attacker.js";
import { type Sandbox, bundleForImport } from "./sandbox.js";
import type { AttackClass, Exploit } from "./types.js";

/** How ground truth for an input is obtained. */
export type OracleGroundTruth =
  // Run `input` as a shell command; fired = the benign marker actually executed. The default for
  // command-approval controls (the openclaw exec-approval class).
  | "shell-exec"
  // A custom JS boolean body evaluated in the driver with `input` and `MARK` in scope, returning
  // whether the input's real behavior fired the marker (e.g. importing the target and calling it).
  | { readonly expr: string };

export interface DifferentialOracleSpec {
  readonly attackClass: AttackClass;
  /** Planted-flawed fixture the canary probes to prove the lane is LIVE. */
  readonly canaryFixtureDir: string;
  /** Which target file(s) hold the security-decision control this oracle probes. */
  handles(file: string): boolean;
  /**
   * Adversarial inputs. Each MAY contain the token `{{MARK}}`, replaced per-run by a fresh
   * unguessable marker. The (substituted) input is BOTH what the control judges and — for
   * `shell-exec` ground truth — what is run.
   */
  readonly corpus: readonly string[];
  /**
   * The target-specific half: a JS boolean expression evaluated in the driver with `m` = the
   * imported target module and `input` = the (marker-substituted) corpus item. TRUE means the
   * control BELIEVES this input safe / allowed / auto-approvable — i.e. it calls the target's own
   * decision API (e.g. `m.planShellAuthorization(input).trustMode === "executable"`).
   */
  readonly beliefExpr: string;
  /** How ground truth is obtained; defaults to `shell-exec`. */
  readonly groundTruth?: OracleGroundTruth;
  /** Human label for the probed control, used in the sink/summary text. */
  readonly beliefLabel?: string;
  /** Optional lead scanner contributed to the free sweep. */
  staticLeads?(source: string): StaticLead[];
}

/** Builds the .mjs driver that runs belief-vs-ground-truth over the corpus inside the sandbox. */
function buildOracleDriver(spec: DifferentialOracleSpec, moduleRel: string, marker: string): string {
  const corpus = spec.corpus.map((c) => c.split("{{MARK}}").join(marker));
  const gt = spec.groundTruth ?? "shell-exec";
  const groundTruthBody =
    gt === "shell-exec"
      ? `
    try {
      const out = execSync(input, { shell: true, encoding: "utf8", timeout: 4000, stdio: ["ignore", "pipe", "pipe"] });
      return String(out).includes(MARK);
    } catch (e) { return String((e && e.stdout) || "").includes(MARK); }`
      : `
    ${gt.expr}`;
  return `
import { execSync } from "node:child_process";
let m;
try { m = await import(${JSON.stringify("./" + moduleRel)}); }
catch (e) { process.stdout.write("IMPORT_FAIL:" + ((e && e.message) || e) + "\\n"); process.exit(0); }
const MARK = ${JSON.stringify(marker)};
const corpus = ${JSON.stringify(corpus)};
function groundTruthFired(input) {${groundTruthBody}
}
for (const input of corpus) {
  let believedSafe = false;
  try { believedSafe = Boolean(${spec.beliefExpr}); } catch (e) {}
  if (!believedSafe) continue;             // control says unsafe -> it prompts; not a bypass
  let fired = false;
  try { fired = Boolean(groundTruthFired(input)); } catch (e) {}
  if (fired) process.stdout.write("RK_DIVERGENCE " + JSON.stringify(input) + "\\n");
}
`.trim();
}

/** Turns a differential-oracle spec into a raeuberkrebs Attacker lane. */
export function differentialOracleAttacker(spec: DifferentialOracleSpec): Attacker {
  const label = spec.beliefLabel ?? "security-decision control";
  return {
    attackClass: spec.attackClass,
    canaryFixtureDir: spec.canaryFixtureDir,
    handles: (file) => spec.handles(file),
    staticLeads: (source) => (spec.staticLeads ? spec.staticLeads(source) : []),
    hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
      const exploits: Exploit[] = [];
      const seen = new Set<string>();
      for (const file of files) {
        if (!spec.handles(file)) continue;
        const marker = freshMarker();
        const driverRel = `.raeuber-oracle-${marker}.mjs`;
        sandbox.writeFile(driverRel, buildOracleDriver(spec, bundleForImport(sandbox, file) ?? file, marker));
        const run = sandbox.exec(`${nodeRunCommand(targetDir)} ${driverRel} 2>&1`, 20_000);
        const out = run.stdout + run.stderr;
        for (const rawLine of out.split("\n")) {
          const matched = rawLine.match(/^RK_DIVERGENCE (.+)$/);
          if (!matched) continue;
          let input: string;
          try {
            input = JSON.parse(matched[1]);
          } catch {
            continue;
          }
          const key = `${file}::${input}`;
          if (seen.has(key)) continue;
          seen.add(key);
          exploits.push({
            attackClass: spec.attackClass,
            proof: "belief-diverged",
            file,
            line: 1,
            sink: `belief:${label}`,
            summary:
              `The ${label} judged \`${input}\` safe/allowed, but running it executed the benign ` +
              `marker — its belief diverges from actual behavior (a bypass of its own gate).`,
            payload: input,
            evidence:
              `belief=safe AND ground-truth fired the marker for: ${input}\n` + out.slice(0, 400),
          });
        }
      }
      return exploits;
    },
  };
}
