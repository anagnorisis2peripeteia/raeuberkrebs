#!/usr/bin/env node
import { existsSync, readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { resolve, join } from "node:path";

const repo = resolve(process.cwd(), process.argv[2] ?? ".");
const repoTaintRoot = resolve(repo, "taint");
const explicitRules = process.argv.slice(3);

function fail(msg, code = 1) {
  console.error(`[raeuberkrebs:taint-sweep] ${msg}`);
  process.exit(code);
}

if (!existsSync(repo)) fail(`repo path does not exist: ${repo}`);
if (!existsSync(repoTaintRoot) && explicitRules.length === 0) {
  fail(`taint rule directory missing: ${repoTaintRoot}`);
}

const rules =
  explicitRules.length > 0
    ? explicitRules.map((r) => resolve(process.cwd(), r))
    : readdirSync(repoTaintRoot)
        .filter((f) => f.endsWith(".yaml"))
        .map((f) => join(repoTaintRoot, f));

if (rules.length === 0) fail("no semgrep rule files found", 1);

const args = ["--json", ...rules.flatMap((r) => ["--config", r]), repo];

let raw;
try {
  raw = execFileSync("semgrep", args, {
    encoding: "utf8",
    cwd: repo,
    maxBuffer: 64 * 1024 * 1024,
    timeout: 120_000,
  });
} catch (err) {
  if (err.status === 1) {
    raw = err.stdout?.toString() ?? "";
  } else if ((err.code || "") === "ENOENT") {
    fail("semgrep is not installed in PATH. install semgrep and retry", 1);
  } else {
    fail(err.message);
  }
}

if (!raw) {
  console.log("[]");
  process.exit(0);
}

let json;
try {
  json = JSON.parse(raw);
} catch {
  fail("semgrep returned non-JSON output", 1);
}

const results = Array.isArray(json?.results) ? json.results : [];
const rows = results.map((result) => {
  const meta = result.extra?.metavars ?? {};
  const source = meta.$SOURCE?.start ? { line: meta.$SOURCE.start.line, col: meta.$SOURCE.start.col } : null;
  const urlMeta = meta.$URL?.start ? { line: meta.$URL.start.line, col: meta.$URL.start.col } : null;
  const sinkMeta = meta.$SINK?.start ? { line: meta.$SINK.start.line, col: meta.$SINK.start.col } : null;

  return {
    rule: result.check_id,
    file: result.path,
    line: result.start?.line ?? null,
    sinkLine: result.end?.line ?? null,
    source,
    sink: sinkMeta ?? urlMeta ?? null,
    sourceExpr: result.extra?.metavars?.$SOURCE?.abstract_content ?? null,
    sinkExpr: result.extra?.metavars?.$URL?.abstract_content ?? result.extra?.metavars?.$SINK?.abstract_content ?? null,
    message: result.extra?.message,
  };
});

process.stdout.write(JSON.stringify(rows, null, 2));
process.exit(0);
