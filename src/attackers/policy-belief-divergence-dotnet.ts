import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { differentialOracleDotnet } from "./dotnet-oracle.js";

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * C# counterpart of PolicyBeliefDivergenceAttacker — the drive-and-prove command-approval oracle for
 * .NET targets. It probes a `bool IsCommandSafe(string)`-shaped gate's BELIEF against GROUND TRUTH
 * (does the command actually run the benign marker?) by compiling the target + a driver and running
 * the corpus. The planted fixture (`fixtures/differential-oracle-dotnet/Approval.cs`) ships a
 * `command`-carrier flaw so the lane proves itself LIVE.
 *
 * This is also the copy-me TEMPLATE for a real C# target (see PLAYBOOK.md): point `handles` at the
 * target's approval-control file and set `methodName` to its decision method. The compiled-language
 * belief is "the discovered `bool <name>(string)` returns true", so no per-target expression is
 * needed — only which file and which method.
 */
export const PolicyBeliefDivergenceDotnetAttacker = differentialOracleDotnet({
  attackClass: "policy-belief-divergence",
  canaryFixtureDir: resolve(HERE, "..", "..", "fixtures", "differential-oracle-dotnet"),
  beliefLabel: "command-approval control",
  handles: (file) => file === "Approval.cs",
  methodName: /^IsCommandSafe$/,
  // `{{MARK}}` is replaced per-run by a fresh unguessable marker; the input is both what the control
  // judges and what shell-exec runs. The first diverges (believed safe + fires); the second the toy
  // correctly deems unsafe (so it is skipped, not a false positive).
  corpus: ["command echo {{MARK}}", "echo {{MARK}}"],
});
