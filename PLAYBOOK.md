# Playbook — Differential-Oracle lanes

*How raeuberkrebs finds "the security control **believes** an input is safe, but it actually **runs**"
— and how to recreate one on a new target.*

## What it is

Most lanes drive an adversarial payload through a code **sink** (`exec`, `readFile`, …) and prove a
fired marker. A **differential oracle** is the inverse: it probes the target's **own
security-decision function** (an approval gate, allowlist matcher, URL/SSRF policy, authz classifier,
sanitizer) and diffs its **belief** against **ground truth**.

For each adversarial input:
- **belief** — does the control *believe* the input is safe / allowed / auto-approvable? (call its API)
- **ground truth** — does running the input actually fire the benign marker?
- **divergence** = `belief === safe && marker fired` → a proven bypass of the control's own gate.

This still obeys the family rule — **evidence or it didn't count**: a belief that merely *looks* wrong
is a lead; belief-safe **and** the marker executed is a finding.

The primitive lives in [`src/differential-oracle.ts`](src/differential-oracle.ts). It owns the driver
generation, sandbox orchestration, divergence parsing, Exploit construction, and canary liveness. A
concrete lane supplies only the target-specific pieces.

## Recreate one on a new target (4 fields)

Copy [`src/attackers/policy-belief-divergence.ts`](src/attackers/policy-belief-divergence.ts) and set:

1. **`handles(file)`** — the target file(s) exporting the security-decision function.
2. **`beliefExpr`** — a JS boolean, evaluated with `m` (the imported target module) and `input` in
   scope, TRUE when the control **believes** `input` safe/allowed. *This is the only target-specific
   logic* — it calls the target's own decision API.
3. **`corpus`** — adversarial inputs; put `{{MARK}}` where a benign marker should run (replaced
   per-run by a fresh unguessable marker).
4. **`groundTruth`** — `"shell-exec"` (default: run `input` as a command, fired = marker echoed) or a
   custom `{ expr }` (a JS boolean body with `input`/`MARK` in scope for non-shell targets).

Then add it to `ATTACKERS` in `src/runner.ts`, and ship a planted-flawed fixture its canary fires
(mirror `fixtures/differential-oracle-node/approval.js`). The canary proves the lane LIVE every run.

## Worked examples — the openclaw exec-approval finds this was distilled from

Each maps 1:1 onto a spec. (Belief calls openclaw's own exec-approval API; ground truth runs the
command and checks the marker.)

**1. Tool-option / carrier bypass — `GHSA-f2hf`, `GHSA-ghpx`**
- `beliefExpr`: the analyzer grants `"executable"` trust to an allow-listed executable, e.g.
  `m.planShellAuthorization({command: input}) …trustMode === "executable"` **and** `matchAllowlist` hits.
- `corpus`: `["git -c alias.x='!echo {{MARK}}' x", "command echo {{MARK}}", "env X=1 echo {{MARK}}", "ssh -o ProxyCommand='echo {{MARK}}' h", …]`
- divergence: the analyzer auto-approves a **carrier** (git `-c`, `command`, ssh `ProxyCommand`) whose
  inner command runs the marker.

**2. Allow-always any-args reuse — `GHSA-5wg5`**
- `beliefExpr`: allow-always a **benign** subcommand, then a **dangerous** sibling matches the persisted
  entry — `matchAllowlist(resolveAllowAlwaysPatternEntries(benign), dangerous) !== null`.
- `corpus` (benign→dangerous pairs): `npm run build → npm exec {{MARK}}`, `cargo build → cargo run`,
  `rake x → rake {{MARK}}`, …
- divergence: allow-always'ing a benign subcommand auto-approves the tool's arbitrary-code subcommands.

**3. Wrapper-leaf / resolver — `GHSA-ghpx`**
- `beliefExpr`: `m.planShellAuthorization({command: "watch echo {{MARK}}"}) …executable` with `watch`
  allow-listed and never unwrapped.
- divergence: the resolver never unwrapped `watch`/`strace`/… so their inner command auto-approved.

## C# (.NET) targets — the compiled-language oracle

The Node oracle `import()`s a module and evaluates a JS `beliefExpr`. C# is compiled, so
[`src/attackers/dotnet-oracle.ts`](src/attackers/dotnet-oracle.ts) instead assembles the target
source + a generated `Driver.cs` + a csproj into an isolated console project, `dotnet build`s it, and
runs the belief-vs-ground-truth loop in-process — the same drive-and-prove machinery the .NET
command-injection lane uses (`dotnet.ts`). A file that needs the rest of its project to compile just
won't build in isolation → an honest miss, never a false pass. Two shapes ship, because a C# control's
ground truth is typed, not duck-typed:

**A. Command-approval** — `differentialOracleDotnet({ ... })`, the exec-approval class in C#. Point it
at a `bool Decision(string)` gate and supply `methodName` + `corpus` (belief = the gate returns true;
ground truth = running the command fires the marker). Copy-me lane +
canary: [`policy-belief-divergence-dotnet.ts`](src/attackers/policy-belief-divergence-dotnet.ts) /
[`fixtures/differential-oracle-dotnet/Approval.cs`](fixtures/differential-oracle-dotnet/Approval.cs).

```ts
differentialOracleDotnet({
  attackClass: "policy-belief-divergence",
  canaryFixtureDir: <planted Approval.cs dir>,
  handles: (f) => f === "TargetApproval.cs",
  methodName: /^IsCommandSafe$/,          // the discovered `bool <name>(string)` gate
  corpus: ["command echo {{MARK}}", "echo {{MARK}}"],
})
```

**B. Authz fail-open** (the C# *differential-authorization* lane) — `authzFailOpenDotnet({ ... })`.
Statically-typed C# has no generic duck-typed context, so the Node BAC's entrypoint-pairing doesn't
port; the tractable, policy-free invariant is instead the **null-authority** one: a role/permission
gate MUST deny a principal carrying no roles/claims. The lane discovers a
`bool IsAuthorized(ClaimsPrincipal)`-shaped gate, drives it with `new ClaimsPrincipal(new
ClaimsIdentity())`, and fires when it returns true (admitted the role-less caller, CWE-862/863). It
needs no policy knowledge and correctly does NOT fire on a sound gate — e.g. microsoft/mcp-gateway's
`BuiltinToolAuthorizer` (`GetUserRoles().Any(r => allowed.Contains(r))` denies the empty set). Copy-me
lane + canary: [`authz-fail-open-dotnet.ts`](src/attackers/authz-fail-open-dotnet.ts) /
[`fixtures/authz-fail-open-dotnet/Authorizer.cs`](fixtures/authz-fail-open-dotnet/Authorizer.cs).

```ts
authzFailOpenDotnet({
  attackClass: "broken-access-control",
  canaryFixtureDir: <planted Authorizer.cs dir>,
  handles: (f) => f === "TargetAuthorizer.cs",   // methodName defaults to the common authz verbs
})
```

Both drive-and-prove lanes need `dotnet` on the box (the sandbox must carry the SDK; the default
apple-container node image does not — run with `{ prefer: "local" }` on a dotnet host, or a dotnet
crabbox image). Same fail-closed liveness as every lane: the planted C# fixture must fire or the lane
is quarantined.

## Why this is a *method*, not a push-button lane

The belief half is inherently target-specific — you have to point it at the target's real decision API.
The primitive makes the *mechanical* half (corpus run, belief-vs-truth diff, marker proof, liveness)
reusable, so the next oracle is four fields (Node) or two (compiled C#, where the belief is "the
discovered decision method returns true"), not a bespoke harness. That is the part that generalized.
