# Canary fixture — C# command-approval differential oracle

`Approval.cs` ships a **planted** command-approval flaw: `IsCommandSafe` whitelists the `command `
builtin prefix, which is a *carrier* (`command echo X` runs `echo`). It is a miniature of the real
openclaw `command`-builtin exec-approval bypass (GHSA-ghpx).

The lane `DifferentialOracleDotnetAttacker` (see `src/attackers/dotnet-oracle.ts`) must fire against
this fixture every run — it drives the corpus `["command echo <marker>", "echo <marker>"]`, and the
first item diverges (believed safe **and** the marker executes) while the second is correctly judged
unsafe (proving the lane does not false-positive). If the canary does not fire, the lane is
quarantined (fail-closed).

Do **not** "fix" this file — it is a liveness target, not production code.
