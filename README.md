# Räuberkrebs

[![CI](https://github.com/anagnorisis2peripeteia/raeuberkrebs/actions/workflows/ci.yml/badge.svg)](https://github.com/anagnorisis2peripeteia/raeuberkrebs/actions/workflows/ci.yml)

The **red-team** member of the krebs family (marmorkrebs=mutation, kanarienkrebs=runtime,
einsiedlerkrebs=invariants, signalkrebs=concurrency). A PR-scoped **code-security** gate that
*attacks* the entrypoints a change touched with adversarial payloads, **executes** them in a
sandbox, and fails closed on any payload that actually **fires** — a reproducible PoC.

> Räuberkrebs = the robber/coconut crab (*Birgus latro*), which cracks open shells. For **authorized
> testing of your own code only.**

## The rule: evidence or it didn't count

A finding is a payload that *executed* and produced observed proof of compromise (an injected
`echo` marker ran, a decoy secret was read out, the process crashed). A static "this looks
injectable" is a **lead** for the attacker, never a finding. Payloads are **benign by construction**
— they inject a unique random marker, never a destructive command — so proving a vuln does no harm;
the sandbox is defense-in-depth.

Verdicts (fail-closed, only `clean` exits 0): `clean` / `vulnerable`(2) / `insufficient`(3, surface
unreachable) / `lane-dead`(3, a lane couldn't fire its own planted-exploit canary) / `error`(1).

## Usage

```bash
raeuberkrebs --dir <repo> --base <ref> [--report-file <path>] [--prefer crabbox|local] [--json]
```

Each lane first proves itself **live** by exploiting its planted-vulnerable fixture; a lane that
can't is quarantined (never a silent pass). PoCs run in a **crabbox** sandbox (throwaway, no network,
no host FS); a reduced-isolation local copy is the fallback when crabbox isn't provisioned.

## Status

**50 execute-the-PoC lanes** across Node/TypeScript, Python, Go, Swift, and C#/.NET. Every lane proves
itself **live** against a planted-vulnerable fixture each run (the canary rule — a lane that can't
exploit its own fixture is quarantined, never a silent pass). The full red-team suite runs on every
push and PR (see the CI badge above).

Lane families:

- **Injection** — command-injection (Node/Swift/Python/Go/.NET), SQL-injection (Node/Swift),
  CSV/formula-injection (Node/Swift), unsafe-exec, eval-of-parsed-AST (`#107`), secondary-interpreter
  (SSTI / log / CSV-formula / CRLF-header), prompt-injection (`#86`, static).
- **Path / filesystem** — path-traversal (Node/Swift/Python/Go/.NET), name/identifier-field traversal
  (`#102`), zip-slip, untrusted-search-path (`#101`).
- **SSRF** — Node / Swift / .NET, with trust-boundary and check-vs-connect differentials.
- **Authorization & access** — exec-authorization (argv-policy differential), control-plane (stateful
  escalation), broken-access-control, broken-object-access, missing-authentication.
- **Command-guard coverage differentials** (`policy-belief-divergence`, Python) — reverse-shell (`#94`),
  defense-evasion (`#95`), catastrophic-destruction (`#98`), secure-erase (`#99`), pipe-wrapper
  (`#100`), wrapper-completeness (`#96`), sensitive-path-spelling (`#92`), decode-eval (`#105`),
  assignment-indirection (`#93`), guard-normalization. Each fires when a guard flags a control command
  but clears an equivalent carrier the denylist misses (CWE-693 fail-open).
- **Secret exposure** — redaction-completeness (`#89`), redaction mode-differential (`#91`).
- **Deserialization & merge** — unsafe-deserialization (Node/Python/.NET), prototype-pollution.
- **Other** — resource-exhaustion (Node/Swift), stored (second-order) taint, insecure-default (`#103`).

Primitives: the crabbox/local sandbox with a `writeFile` PoC-drop, git-diff scoping, the fail-closed
result model, canary-liveness in the runner, and the CLI gate.

## Platform

The full suite is verified on **macOS** (CI runs on `macos-latest`). The Node/Python/Go/.NET lanes run
on Linux too, but the **Swift** lanes need a Swift toolchain — and stock-Linux Swift lacks the libcurl
networking / SQLite backends the SSRF and SQLi Swift lanes drive, so full-suite parity is macOS-only
for now. Lanes whose toolchain is absent skip or are quarantined rather than failing the gate.
