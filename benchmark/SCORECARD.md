# Lane scorecard — real-corpus recall + held precision

The destination of wayfinder map [#130](https://github.com/anagnorisis2peripeteia/raeuberkrebs/issues/130), made concrete. One row per execute-driven lane. A lane **passes** the [#132](https://github.com/anagnorisis2peripeteia/raeuberkrebs/issues/132) contract when it clears **≥80% recall of the function-shaped corpus subset** at **0 false positives** on its sound negative control, with its canary **live** and a **proven-effect** oracle.

- **Recall (drivable)** = `HIT / (HIT + MISS)` on the real corpus — `lane-not-live` runs (canary didn't fire in that sandbox) are excluded from the denominator and tracked separately, because they are a *liveness* problem, not a *detection* miss.
- **Server-owed** = entries whose sink is only reachable by booting a server (owed to the [#129](https://github.com/anagnorisis2peripeteia/raeuberkrebs/issues/129) HTTP-handler driver), not counted against the function-driver.
- Corpus = [SecBench.js](https://github.com/cristianstaicu/SecBench.js) (server-side-JS CVEs). Measured via `benchmark/secbench-recall.mjs` / `scratchpad/phase3-harness.mjs`.

| Lane | fn-shaped recall (drivable) | server-owed (#129) | neg-control FP | canary live | proven-effect oracle | **verdict** |
|---|---|---|---|---|---|---|
| prototype-pollution | **4 / 13 (31%)** | 0 | 0 | ⚠ 7/20 runs `lane-not-live` | ✅ fresh `{}` polluted | **FAIL — below 80%; + canary flakiness** |
| command-injection | 3 / 10 (30%) | — | 0 | ✅ | ✅ marker file executed | **FAIL — below 80%** |
| path-traversal | n/a (0 fn-shaped in corpus) | **170 (100%)** | 0 | ✅ | ✅ decoy content exfiltrated | **BLOCKED on #129** (recall entirely server-shaped) |

## Notes per lane

- **prototype-pollution** — the entrypoint-driver-style port lifted real recall from ~0 → 4/13. Two blockers remain to reach the bar, each a follow-up ticket:
  1. **9 driven-but-MISS** vulnerable packages (e.g. `aurelia-path`, `101`, `bmoor`, `bodymen`) — the driver reaches an export but the specific call shape / subpath entrypoint isn't hit.
  2. **7/20 `lane-not-live`** — the lane's own canary intermittently fails to fire in a cold sandbox → the lane is quarantined and can't report. A liveness/flakiness bug independent of detection.
- **command-injection** — ported earlier (0 → 3/10); a harvest pass against the survey's winnable list is queued.
- **path-traversal** — every real CVE is `http.createServer` + a crafted request; the lane's contracts (canary / boundary-symlink / no-FP) all pass, but its corpus recall is *entirely* gated on the #129 HTTP-handler driver. Correctly BLOCKED, not FAILED.

_This scorecard is honest by design: a lane that isn't at standard says so, and each gap is a ticket, not a silent omission._
