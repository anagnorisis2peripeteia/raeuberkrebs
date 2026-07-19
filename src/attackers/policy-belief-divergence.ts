import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { differentialOracleAttacker } from "../differential-oracle.js";

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * Reference / canary differential-oracle lane. It probes a command-approval control's BELIEF
 * (`isCommandSafe`) against GROUND TRUTH (does the command actually run the benign marker?) and
 * reports every input the control auto-approved that nonetheless executed — a gate bypass. The
 * planted fixture (`fixtures/differential-oracle-node/approval.js`) ships a `command`-carrier flaw so
 * the lane proves itself LIVE.
 *
 * This is also the copy-me TEMPLATE for a real target (see PLAYBOOK.md): point `handles` at the
 * target's security-decision module and set `beliefExpr` to call that module's decision API. The
 * three openclaw exec-approval finds are worked examples of exactly that in PLAYBOOK.md.
 */
export const PolicyBeliefDivergenceAttacker = differentialOracleAttacker({
  attackClass: "policy-belief-divergence",
  canaryFixtureDir: resolve(HERE, "..", "..", "fixtures", "differential-oracle-node"),
  beliefLabel: "command-approval control",
  handles: (file) => file === "approval.js",
  // `{{MARK}}` is replaced per-run by a fresh unguessable marker; the input is both what the control
  // judges and what shell-exec runs. The first diverges (believed safe + fires); the second is a
  // control the toy correctly deems unsafe (so it is skipped, not a false positive).
  corpus: ["command echo {{MARK}}", "echo {{MARK}}"],
  beliefExpr: `typeof m.isCommandSafe === "function" && m.isCommandSafe(input) === true`,
  // groundTruth defaults to "shell-exec": run `input`, fired = the marker echoed.
});
