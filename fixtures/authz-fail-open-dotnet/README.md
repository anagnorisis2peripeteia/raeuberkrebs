# Canary fixture — C# authz fail-open oracle

`Authorizer.cs` ships a **planted** authorization flaw: `IsAuthorized` returns `true` for a caller
with **no roles** (it assumes a role-less principal is an internal/system caller). A correct
role/permission gate must **deny** the null-authority principal.

The lane `AuthzFailOpenDotnetAttacker` (see `src/attackers/dotnet-oracle.ts`) must fire against this
fixture every run — it constructs the weakest-possible principal
(`new ClaimsPrincipal(new ClaimsIdentity())`, unauthenticated, zero role claims), calls the gate, and
reports a divergence when the gate admits it. The invariant needs no policy knowledge (a role gate
must deny a role-less caller), and it correctly does **not** fire on the sound shape
`roles.Any(r => Allowed.Contains(r))`, which denies the empty set. If the canary does not fire, the
lane is quarantined (fail-closed).

Do **not** "fix" this file — it is a liveness target, not production code.
