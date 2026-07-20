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

## Why this is a *method*, not a push-button lane

The belief half is inherently target-specific — you have to point it at the target's real decision API.
The primitive makes the *mechanical* half (corpus run, belief-vs-truth diff, marker proof, liveness)
reusable, so the next oracle is four fields, not a bespoke harness. That is the part that generalized.
