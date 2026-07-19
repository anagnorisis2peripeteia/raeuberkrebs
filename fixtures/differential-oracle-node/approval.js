// PLANTED-FLAWED command-approval control (raeuberkrebs canary fixture — NOT production code).
//
// This toy security-decision function auto-approves any `command <x>` invocation as "safe". That is
// a faithful miniature of a real carrier bypass: the `command` shell builtin runs its arguments as a
// command, so `command echo <marker>` is BELIEVED safe here yet actually EXECUTES. The
// differential-oracle lane must catch that divergence (belief=safe, marker fires) to prove itself live.
export function isCommandSafe(cmd) {
  if (typeof cmd !== "string") return false;
  // FLAW: trusts the `command` builtin without unwrapping the inner command it runs.
  if (cmd.startsWith("command ")) return true;
  // A correctly-modeled safe case: a bare `true` runs nothing dangerous.
  return cmd === "true";
}
