# Räuberkrebs

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

## Status — Chunk 0 (built + verified)

- Lane: **command-injection** (Node `.js/.cjs`, Swift `.swift`, Python `.py`, Go `.go`), detect shell
  sinks (`child_process`, `Process`, `subprocess shell=True`, `os.system`, `exec.Command("sh","-c",...)`)
  → drive marker payloads through the exported/parsed entrypoint → prove via the executed marker.
  Fires on the planted fixture + novel code; no false positive on safe non-shell exec paths.
- Lane: **path-traversal** (Node `.js/.cjs`, Swift `.swift`, Python `.py`, Go `.go`), detect filesystem
  joins/reads with untrusted components (`path.join`, `filepath.Join`, `String(contentsOfFile:)`,
  `open(... )`) → prove via marker-secrets read outside base path.
- Lane: **exec-authorization** (Node `.js/.cjs`), detect differential command launch policy where policy-facing
  wrappers call a launcher that still accepts policy-unsafe equivalent argv forms (for example `node --eval`
  bypassing `node -e`) → prove with benign argv differential payloads and marker execution.
- Lane: **control-plane** (Node `.js/.cjs`), detect stateful policy-control escalation by driving low-privileged
  config mutation first and then executing a marker-protected action only after that mutation succeeds.
- Lane: **sql-injection** (Node `.js/.cjs`), broadened sink matching now includes `prepare(...).all/run/get/query()`
  flows so prepared-query + dynamic-execution patterns on SQLite/driver-like APIs are exercised against planted
  fixtures.
- Primitives: the crabbox/local sandbox with a `writeFile` PoC-drop, git-diff scoping, the
  fail-closed result model, canary-liveness in the runner, the CLI gate.

**Next (roadmap):** path-traversal static hardening is now live, plus the remaining C# static lanes (unsafe-exec, SQLi, weak-crypto, etc.) are shipping in follow-up chunks; current scope remains PR validation, live canary discipline, and discovery-tooling integration.
