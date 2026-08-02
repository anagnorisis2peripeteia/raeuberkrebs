# Lane scorecard — real-corpus recall + held precision

The destination of wayfinder map [#130](https://github.com/anagnorisis2peripeteia/raeuberkrebs/issues/130), made concrete. One row per execute-driven lane. A lane **passes** the [#132](https://github.com/anagnorisis2peripeteia/raeuberkrebs/issues/132) contract when it clears **≥80% recall of the function-shaped corpus subset** at **0 false positives** on its sound negative control, with its canary **live** and a **proven-effect** oracle.

- **Recall (drivable)** = `HIT / (HIT + MISS)` on the real corpus — `lane-not-live` runs (canary didn't fire in that sandbox) are excluded from the denominator and tracked separately, because they are a *liveness* problem, not a *detection* miss.
- **Server-owed** = entries whose sink is only reachable by booting a server (owed to the [#129](https://github.com/anagnorisis2peripeteia/raeuberkrebs/issues/129) HTTP-handler driver), not counted against the function-driver.
- Corpus = [SecBench.js](https://github.com/cristianstaicu/SecBench.js) (server-side-JS CVEs). Measured via `benchmark/secbench-recall.mjs` / `scratchpad/phase3-harness.mjs`.

| Lane | fn-shaped recall (drivable) | server-owed (#129) | neg-control FP | canary live | proven-effect oracle | **verdict** |
|---|---|---|---|---|---|---|
| prototype-pollution | **9 / 16 (56%)** | 0 | 0 | ✅ (canary robust; `no-sink` excluded) | ✅ fresh `{}` polluted | **FAIL — below 80%; remaining 7 need distinct capabilities** |
| command-injection | **10 / 18 (56%)** | (server-shaped remainder → #129) | 0 | ✅ | ✅ marker file executed | **FAIL — below 80%; ~2× via default-fn driving** |
| path-traversal | n/a (0 fn-shaped in corpus) | **170 (100%)** | 0 | ✅ | ✅ decoy content exfiltrated | **BLOCKED on #129** (recall entirely server-shaped) |
| redos / resource-exhaustion | **0 / 6 (0%)** | 0 | 0 | ✅ | ✅ input-caused hang | **BLOCKED on #139** (generic inputs can't trigger real regexes) |

## Notes per lane

- **prototype-pollution** — recall lifted ~0 → **9/16 (56%)** across three commits: default-function-export driving, a sink gate keyed on the real pollution WRITE primitive (computed-member assignment `obj[key]=…`, nested forms included), and honest `no-sink` accounting. `lane-not-live` was diagnosed as a measurement artifact, not canary fragility (#136). The remaining **7 MISS each need a DISTINCT capability**, not a shape tweak — the key finding that **"function-shaped" ≠ "uniformly drivable"**:
  - `.ts` sink not driven — `confinit`, `class-transformer` (a TypeScript-entrypoint capability, cf. #129 for HTTP).
  - subpath entrypoint — `101` (`require("101")` throws; the real sink is `101/set`).
  - bespoke structured input — `changeset` (patch-array `apply([{key:[…]}], obj)`), `component-flatten`, `confucious`, `cached-path-relative` (not polluted by any of the standard object/flat/dotpath/key-parts shapes).
  Tracked in the 56%→80% endgame ticket. **This surfaces a question about the #132 bar:** 80% of a "function-shaped" class assumed uniform drivability; the real ceiling with a bounded JS driver is lower until the `.ts` / subpath / structured-input capabilities land.
- **redos / resource-exhaustion** — the export-resolution port (default-function / nested-method driving) now *reaches* the vulnerable regex fn (brace-expansion, ansi-html, color-string were all applicable+live but `fired 0`), but recall is **0/6**: the driver's generic evil inputs (`"a".repeat(≤42)+"!"`) can't trigger real ReDoS regexes, which need a **tailored** attack (format prefix + long pump + failing suffix, e.g. `"hwb("+"1".repeat(50000)+"!"`). Blocked on the regex-aware attack-string generator (**#139**) — the redos analog of "function-shaped ≠ uniformly drivable": *detectable-regex ≠ generically-triggerable*.
- **command-injection** — 0 → 3/10 (initial port) → **10/18 (56%)** after the same `module.exports = function` drive-default fix that lifted prototype-pollution and redos (`local-devices`, `growl` and friends were skipped for having no named export). The recurring export-resolution bug is now the campaign's single highest-ROI fix. Remaining 8 MISS are the server-shaped / async-timing tail (→ #129).
- **path-traversal** — every real CVE is `http.createServer` + a crafted request; the lane's contracts (canary / boundary-symlink / no-FP) all pass, but its corpus recall is *entirely* gated on the #129 HTTP-handler driver. Correctly BLOCKED, not FAILED.

_This scorecard is honest by design: a lane that isn't at standard says so, and each gap is a ticket, not a silent omission._
