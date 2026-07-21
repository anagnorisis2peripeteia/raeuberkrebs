#!/usr/bin/env node
// Run the Swift differential-oracle lane over a whole repo: static discovery of decision functions,
// then the belief-vs-ground-truth execute hunt on the candidates. Usage: run-oracle.mjs <repo-dir>
import { readFileSync, readdirSync, mkdtempSync } from "node:fs";
import { join, relative } from "node:path";
import { tmpdir } from "node:os";
import { DifferentialOracleSwiftAttacker } from "../dist/attackers/differential-oracle-swift.js";
import { openSandbox } from "../dist/sandbox.js";

const repo = process.argv[2];
if (!repo) {
  console.error("usage: run-oracle.mjs <repo-dir>");
  process.exit(2);
}
const lane = new DifferentialOracleSwiftAttacker();
const SKIP = new Set([".git", ".build", "node_modules", "DerivedData", ".swiftpm"]);

function walk(dir, acc = []) {
  let entries = [];
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return acc; }
  for (const e of entries) {
    if (e.name.startsWith(".") && e.name !== "." ) continue;
    if (SKIP.has(e.name)) continue;
    const full = join(dir, e.name);
    if (e.isDirectory()) walk(full, acc);
    else if (e.name.endsWith(".swift")) acc.push(full);
  }
  return acc;
}

const all = walk(repo).map((f) => relative(repo, f));
const nonTest = all.filter((f) => !/(^|\/)(Tests?|.*Tests)(\/|\.)/.test(f));

// Static discovery: which files hold decision (belief) candidates the oracle can drive.
const candidates = [];
for (const f of nonTest) {
  let leads = [];
  try { leads = lane.staticLeads(readFileSync(join(repo, f), "utf8")); } catch {}
  if (leads.length) candidates.push({ file: f, leads });
}
console.log(`[oracle] ${repo}`);
console.log(`[oracle] swift files: ${all.length} (non-test ${nonTest.length}); decision-candidate files: ${candidates.length}`);
for (const c of candidates.slice(0, 40)) {
  console.log(`  DECISION ${c.file}: ${c.leads.map((l) => l.sink).join(" | ")}`);
}

// Execute: drive the divergence hunt on candidate files only (each compiled in isolation).
const box = openSandbox(mkdtempSync(join(tmpdir(), "rk-oracle-")), { prefer: "local" });
let exploits = [];
try {
  exploits = lane.hunt(repo, candidates.map((c) => c.file), box);
} finally {
  box.dispose();
}
console.log(`\n[oracle] belief-divergence findings: ${exploits.length}`);
for (const e of exploits) {
  console.log(`  DIVERGENCE ${e.file} [${e.sink}]: ${e.summary}`);
}
process.exit(0);
