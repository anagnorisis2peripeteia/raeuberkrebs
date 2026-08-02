// Phase 3 calibration harness: run raeuberkrebs over real SecBench.js CVEs, measure recall.
// For each vuln: read its metadata (CVE id, vulnerable dep@version, sink file), npm-install the
// vulnerable version into a throwaway dir, run raeuberkrebs on the sink file, and record whether the
// matching lane FIRED. A miss (lane live but fired 0) is a real recall gap → a feature-issue candidate.
//
// Usage: node phase3-harness.mjs <class> <count>   e.g. node phase3-harness.mjs command-injection 5
import { execFileSync, execSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, existsSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// SecBench.js corpus location — override with SECBENCH_DIR so the harness runs off-box (e.g. on a
// remote worker with the corpus on a different drive) without editing the path.
const SECBENCH = process.env.SECBENCH_DIR || "/private/tmp/claude-501/-Users-cameronbeeley/0f82624d-6358-4fa4-9dde-72c349723a04/scratchpad/SecBench.js";
// Resolve the built CLI relative to this harness file so it works from any checkout / drive.
const CLI = process.env.RK_CLI || fileURLToPath(new URL("../dist/cli.js", import.meta.url));
// SecBench class dir -> the raeuberkrebs lane(s) that should catch it.
const CLASS_LANES = {
  "command-injection": ["command-injection"],
  "prototype-pollution": ["prototype-pollution"],
  "path-traversal": ["path-traversal", "zip-slip"],
  redos: ["resource-exhaustion"],
};

const klass = process.argv[2] || "command-injection";
const count = Number(process.argv[3] || 5);
const lanes = CLASS_LANES[klass];
if (!lanes) { console.error("unknown class", klass); process.exit(1); }

const dirs = readdirSync(join(SECBENCH, klass)).filter((d) => existsSync(join(SECBENCH, klass, d, "package.json"))).slice(0, count);

const results = [];
for (const d of dirs) {
  let meta;
  try { meta = JSON.parse(readFileSync(join(SECBENCH, klass, d, "package.json"), "utf8")); } catch { continue; }
  const dep = Object.keys(meta.dependencies || {})[0];
  const ver = meta.dependencies?.[dep];
  const sink = meta.sink; // "relpath:line:col" inside the installed package
  if (!dep || !ver) { results.push({ cve: meta.id, dep: d, status: "no-dep" }); continue; }
  const work = mkdtempSync(join(tmpdir(), "p3-"));
  let fired = null, verdict = null, note = "";
  try {
    writeFileSync(join(work, "package.json"), JSON.stringify({ name: "p3", version: "0.0.0", private: true }));
    execSync(`npm i ${dep}@${ver} --no-audit --no-fund --loglevel=error`, { cwd: work, stdio: "ignore", timeout: 120000 });
    // An entry with no usable sink FILE (empty `sink`, or a `sink` path that isn't present in the
    // installed package) is UNMEASURABLE — there is no specific file to point the scanner at. Record it
    // as `no-sink` rather than running against the package DIR, where a non-matching lane would read as
    // `lane-not-live` and be wrongly blamed as a canary/liveness failure. Keeps the recall denominator
    // honest: `no-sink` is excluded from HIT/MISS, not counted as a dead lane.
    const sinkRel = sink ? join("node_modules", dep, String(sink).split(":")[0]) : "";
    if (!sinkRel || !existsSync(join(work, sinkRel))) {
      note = "no-sink";
      results.push({ cve: meta.id, dep, ver, sink: (sink || "").split(":")[0], verdict: null, fired: null, note });
      console.log(`${note.padEnd(14)} ${(meta.id || d).padEnd(18)} ${dep}@${ver}  (no measurable sink file)`);
      continue; // the `finally` below removes the workdir
    }
    const target = sinkRel;
    let raw;
    try {
      raw = execFileSync("node", [CLI, "--dir", work, "--file", target, "--prefer", "local", "--json"],
        { encoding: "utf8", timeout: 90000, maxBuffer: 32 * 1024 * 1024 });
    } catch (e) {
      // A `vulnerable` verdict exits code 2 (and lane-dead/insufficient exit 3), which execFileSync
      // throws on — but the --json output is still on stdout. Read it off the error.
      raw = (e.stdout || "").toString();
    }
    const jsonLine = raw.trim().split("\n").find((l) => l.trim().startsWith("{")) || "";
    const r = JSON.parse(jsonLine);
    verdict = r.verdict;
    fired = r.lanes.filter((l) => lanes.includes(l.attackClass)).some((l) => l.fired > 0);
    const live = r.lanes.filter((l) => lanes.includes(l.attackClass)).some((l) => l.live);
    note = live ? (fired ? "HIT" : "MISS") : "lane-not-live";
  } catch (e) {
    note = "harness-error:" + (e.message || e).slice(0, 60);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
  results.push({ cve: meta.id, dep, ver, sink: (sink || "").split(":")[0], verdict, fired, note });
  console.log(`${note.padEnd(14)} ${(meta.id || d).padEnd(18)} ${dep}@${ver}  verdict=${verdict}`);
}

const hit = results.filter((r) => r.note === "HIT").length;
const miss = results.filter((r) => r.note === "MISS").length;
console.log(`\n=== ${klass}: recall (drivable) = ${hit}/${hit + miss} HIT; ${miss} MISS; ${results.length - hit - miss} other ===`);
writeFileSync(join(SECBENCH, "..", `p3-${klass}.json`), JSON.stringify(results, null, 2));
