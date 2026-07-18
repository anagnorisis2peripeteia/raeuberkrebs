import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { runRedteam } from "../dist/runner.js";
import { CommandInjectionAttacker } from "../dist/attackers/command-injection.js";
import { SsrfAttacker } from "../dist/attackers/ssrf.js";
import { sweepRepo } from "../dist/sweep.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = join(ROOT, "fixtures", "command-injection-node");
const LOCAL = { sandbox: { prefer: "local" } };

function scratch(files) {
  const dir = mkdtempSync(join(tmpdir(), "rk-test-"));
  writeFileSync(join(dir, "package.json"), '{"name":"s","version":"0.0.0","private":true,"type":"commonjs"}');
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
  return dir;
}

// ESM scratch (package `type: module`) — for .ts/.mjs targets that use `export` syntax.
function scratchModule(files) {
  const dir = mkdtempSync(join(tmpdir(), "rk-test-"));
  writeFileSync(join(dir, "package.json"), '{"name":"s","version":"0.0.0","private":true,"type":"module"}');
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
  return dir;
}

describe("raeuberkrebs command-injection gate", () => {
  it("fires on the planted fixture and returns a proven, evidence-bearing PoC", () => {
    const r = runRedteam(FIXTURE, ["vuln.js"], LOCAL);
    assert.equal(r.verdict, "vulnerable");
    assert.equal(r.exploits.length, 1);
    const e = r.exploits[0];
    assert.equal(e.attackClass, "command-injection");
    assert.equal(e.proof, "marker-executed");
    assert.match(e.evidence, /RAEUBER_[0-9a-f]+/); // the executed marker is the evidence
    assert.ok(e.payload.includes("echo RAEUBER_"));
  });

  it("fires on NOVEL vulnerable code, not just the fixture (generalizes)", () => {
    const dir = scratch({
      "app.js": 'const { execSync } = require("child_process");\nfunction run(cmd){ return execSync("ls " + cmd).toString(); }\nmodule.exports.run = run;\n',
    });
    try {
      const r = runRedteam(dir, ["app.js"], LOCAL);
      assert.equal(r.verdict, "vulnerable");
      assert.equal(r.exploits[0].file, "app.js");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does NOT fire on safe array-arg execFile (no false positive)", () => {
    const dir = scratch({
      "safe.js": 'const { execFileSync } = require("child_process");\nfunction ping(host){ return execFileSync("echo", ["pinging", host]).toString(); }\nmodule.exports.ping = ping;\n',
    });
    try {
      const r = runRedteam(dir, ["safe.js"], LOCAL);
      assert.equal(r.exploits.length, 0);
      assert.notEqual(r.verdict, "vulnerable");
      // the lane still proved itself live against its own fixture
      assert.ok(r.lanes.some((l) => l.attackClass === "command-injection" && l.live));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("no attackable changed file → clean, nothing to red-team", () => {
    const dir = scratch({ "notes.txt": "hello" });
    try {
      const r = runRedteam(dir, ["notes.txt"], LOCAL);
      assert.equal(r.verdict, "clean");
      assert.equal(r.exploits.length, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

const SWIFT_FIXTURE = join(ROOT, "fixtures", "command-injection-swift");

describe("raeuberkrebs command-injection gate (Swift lane)", () => {
  it("fires on the planted Swift fixture — an injected echo executes (marker-executed)", () => {
    const r = runRedteam(SWIFT_FIXTURE, ["vuln.swift"], LOCAL);
    assert.equal(r.verdict, "vulnerable");
    assert.equal(r.exploits.length, 1);
    const e = r.exploits[0];
    assert.equal(e.attackClass, "command-injection");
    assert.equal(e.proof, "marker-executed");
    assert.match(e.evidence, /RAEUBER_[0-9a-f]+/); // the executed marker is the evidence
    assert.ok(e.payload.includes("echo RAEUBER_"));
  });

  it("fires on NOVEL vulnerable Swift, not just the fixture (generalizes)", () => {
    const dir = scratch({
      "app.swift": [
        "import Foundation",
        "func run(_ cmd: String) -> String {",
        '  let p = Process()',
        '  p.executableURL = URL(fileURLWithPath: "/bin/bash")',
        '  p.arguments = ["-c", "ls \\(cmd)"]',
        "  let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe",
        "  try? p.run(); p.waitUntilExit()",
        "  let d = pipe.fileHandleForReading.readDataToEndOfFile()",
        '  return String(data: d, encoding: .utf8) ?? ""',
        "}",
      ].join("\n"),
    });
    try {
      const r = runRedteam(dir, ["app.swift"], LOCAL);
      assert.equal(r.verdict, "vulnerable");
      assert.equal(r.exploits[0].file, "app.swift");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does NOT fire on a safe array-arg Process (no false positive)", () => {
    const dir = scratch({
      "safe.swift": [
        "import Foundation",
        "func ping(_ host: String) -> String {",
        "  let p = Process()",
        '  p.executableURL = URL(fileURLWithPath: "/bin/echo")',
        '  p.arguments = ["pinging", host]',
        "  let pipe = Pipe(); p.standardOutput = pipe",
        "  try? p.run(); p.waitUntilExit()",
        "  let d = pipe.fileHandleForReading.readDataToEndOfFile()",
        '  return String(data: d, encoding: .utf8) ?? ""',
        "}",
      ].join("\n"),
    });
    try {
      const r = runRedteam(dir, ["safe.swift"], LOCAL);
      assert.equal(r.exploits.length, 0);
      assert.notEqual(r.verdict, "vulnerable");
      assert.ok(r.lanes.some((l) => l.attackClass === "command-injection" && l.live));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

const PT_FIXTURE = join(ROOT, "fixtures", "path-traversal-node");

describe("raeuberkrebs path-traversal gate", () => {
  it("fires on the planted fixture — reads a decoy secret via ../ (secret-exfiltrated)", () => {
    const r = runRedteam(PT_FIXTURE, ["vuln.js"], LOCAL);
    assert.equal(r.verdict, "vulnerable");
    const e = r.exploits.find((x) => x.attackClass === "path-traversal");
    assert.ok(e, "expected a path-traversal exploit");
    assert.equal(e.proof, "secret-exfiltrated");
    assert.ok(e.payload.includes("../"));
    assert.match(e.evidence, /RAEUBER_[0-9a-f]+_TRAVERSAL_SECRET/);
  });

  it("does NOT fire when the read is containment-guarded (dynamic attack blocked)", () => {
    const dir = scratch({
      "guarded.js":
        'const fs = require("fs");\nconst path = require("path");\n' +
        "function read(name){\n" +
        '  const base = path.join(__dirname, "public");\n' +
        "  const full = path.resolve(base, name);\n" +
        '  if (!full.startsWith(base + path.sep)) throw new Error("denied");\n' +
        "  return fs.readFileSync(full).toString();\n" +
        "}\nmodule.exports.read = read;\n",
    });
    try {
      const r = runRedteam(dir, ["guarded.js"], LOCAL);
      assert.equal(r.exploits.length, 0, "containment guard must defeat the ../ attack");
      assert.notEqual(r.verdict, "vulnerable");
      assert.ok(r.lanes.some((l) => l.attackClass === "path-traversal" && l.live));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

const SSRF_FIXTURE = join(ROOT, "fixtures", "ssrf-node");

describe("raeuberkrebs ssrf gate", () => {
  it("fires on the planted fixture — an untrusted URL reaches an outbound fetch (oob-request)", () => {
    const r = runRedteam(SSRF_FIXTURE, ["vuln.js"], LOCAL);
    assert.equal(r.verdict, "vulnerable");
    const e = r.exploits.find((x) => x.attackClass === "ssrf");
    assert.ok(e, "expected an ssrf exploit");
    assert.equal(e.proof, "oob-request");
    assert.match(e.payload, /127\.0\.0\.1/);
    assert.match(e.evidence, /RAEUBER_[0-9a-f]+/);
  });

  it("does NOT fire when the fetch host is allowlisted (dynamic attack blocked)", () => {
    const dir = scratch({
      "guarded.js":
        "function get(url){\n" +
        "  const u = new URL(url);\n" +
        '  if (u.hostname !== "api.example.com") throw new Error("host not allowed");\n' +
        "  return fetch(url).then((r) => r.text());\n" +
        "}\nmodule.exports.get = get;\n",
    });
    try {
      const r = runRedteam(dir, ["guarded.js"], LOCAL);
      assert.equal(r.exploits.length, 0, "host allowlist must defeat the loopback-canary attack");
      assert.notEqual(r.verdict, "vulnerable");
      assert.ok(r.lanes.some((l) => l.attackClass === "ssrf" && l.live));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("raeuberkrebs TypeScript / ESM entrypoints", () => {
  it("fires on a TypeScript (.ts) ESM entrypoint — types stripped, imported, driven", () => {
    const dir = scratchModule({
      "app.ts":
        'import { execSync } from "node:child_process";\n' +
        "export function run(cmd: string): string {\n" +
        '  return execSync("ls " + cmd).toString();\n' +
        "}\n",
    });
    try {
      const r = runRedteam(dir, ["app.ts"], LOCAL);
      assert.equal(r.verdict, "vulnerable");
      assert.equal(r.exploits[0].attackClass, "command-injection");
      assert.equal(r.exploits[0].file, "app.ts");
      assert.equal(r.exploits[0].proof, "marker-executed");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("fires SSRF on a .ts entrypoint (oob-request via loopback canary)", () => {
    const dir = scratchModule({
      "svc.ts":
        "export async function pull(url: string): Promise<string> {\n" +
        "  const r = await fetch(url);\n" +
        "  return await r.text();\n" +
        "}\n",
    });
    try {
      const r = runRedteam(dir, ["svc.ts"], LOCAL);
      assert.equal(r.verdict, "vulnerable");
      const e = r.exploits.find((x) => x.attackClass === "ssrf");
      assert.ok(e, "expected an ssrf exploit on the .ts entrypoint");
      assert.equal(e.proof, "oob-request");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("lead precision (#10 cmd-inj, #12 ssrf ranking)", () => {
  it("#10: command-injection ignores db.exec/regex.exec with no child_process import", () => {
    const ci = new CommandInjectionAttacker();
    const sqlite = 'const db = require("better-sqlite3")(":memory:");\nfunction q(n){ return db.exec(`SELECT ${n}`); }\n';
    assert.equal(ci.staticLeads(sqlite).length, 0, "db.exec w/o child_process must not be a cmd-inj lead");
    const real = 'const { execSync } = require("child_process");\nfunction r(h){ return execSync("ls " + h); }\n';
    assert.ok(ci.staticLeads(real).length >= 1, "real child_process exec must still be a lead");
  });

  it("#12: ssrf ranks host-variable high, fixed-host + path-only low", () => {
    const ssrf = new SsrfAttacker();
    const hostVar = ssrf.staticLeads("export const a = (u) => fetch(u);\nexport const b = (h) => fetch(`${h}/api`);");
    assert.ok(hostVar.length >= 2 && hostVar.every((l) => l.priority === "high"), "bare var + ${host}/api are host-variable");
    const pathOnly = ssrf.staticLeads("export const c = (p) => fetch(`https://api.github.com/repos/${p}`);");
    assert.equal(pathOnly[0].priority, "low", "fixed host + /path is path-only");
    const noSlash = ssrf.staticLeads("export const d = (p) => fetch(`https://api.github.com${p}`);");
    assert.equal(noSlash[0].priority, "high", "fixed host with NO slash before the var is subdomain/userinfo-injectable");
  });

  it("#13: down-ranks a config-provenance host (env / literal URL) to low; keeps fn-param high", () => {
    const ssrf = new SsrfAttacker();
    const env = ssrf.staticLeads('const base = process.env.API ?? "https://x";\nexport const a = () => fetch(`${base}/y`);');
    assert.equal(env[0].priority, "low", "env-derived host is config");
    const lit = ssrf.staticLeads('const B = "https://api.example.com";\nexport const b = () => fetch(`${B}/y`);');
    assert.equal(lit[0].priority, "low", "literal-URL const host is config");
    const directEnv = ssrf.staticLeads("export const c = () => fetch(process.env.HOOK_URL);");
    assert.equal(directEnv[0].priority, "low", "direct process.env read is config");
    const param = ssrf.staticLeads("export function f(url){ return fetch(url); }");
    assert.equal(param[0].priority, "high", "fn-parameter URL stays untrusted");
  });
});

describe("guard-coverage (#16 v1 — inter-procedural taint, first cut)", () => {
  it("flags a high-priority sink whose file lacks the project's own guard as a guard-gap", () => {
    const dir = scratchModule({
      "guarded.ts":
        'import { ssrfPolicy } from "./ssrf.js";\n' +
        "export const a = (url: string) => { ssrfPolicy(url); return fetch(url); };\n",
      "unguarded.ts": "export const b = (url: string) => fetch(url);\n",
      "ssrf.ts": 'export function ssrfPolicy(u: string){ if (!u) throw new Error("blocked"); }\n',
    });
    try {
      const r = sweepRepo(dir, { top: 10 });
      const gapFiles = r.guardGaps.filter((g) => g.lane === "ssrf").map((g) => g.file);
      assert.ok(gapFiles.includes("unguarded.ts"), "unguarded fetch should be a guard-gap");
      assert.ok(!gapFiles.includes("guarded.ts"), "fetch in a file referencing the ssrf guard is covered");
      // the covered lead still exists, just not flagged as a gap
      const guardedLead = r.leads.find((l) => l.file === "guarded.ts" && l.lane === "ssrf");
      assert.equal(guardedLead?.guardCovered, true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

const CSV_FIXTURE = join(ROOT, "fixtures", "csv-injection-node");

describe("raeuberkrebs csv-injection gate (models the openclaw google-meet finding)", () => {
  it("fires on a CSV serialiser with no formula-prefix guard (formula-unescaped survives to output)", () => {
    const r = runRedteam(CSV_FIXTURE, ["vuln.js"], LOCAL);
    assert.equal(r.verdict, "vulnerable");
    const e = r.exploits.find((x) => x.attackClass === "csv-injection");
    assert.ok(e, "expected a csv-injection exploit");
    assert.equal(e.proof, "formula-unescaped");
    assert.match(e.payload, /^=RAEUBER_/);
  });

  it("does NOT fire when formula prefixes are neutralised (leading ' prepended)", () => {
    const dir = scratch({
      "safe.js":
        "function toCsv(rows){\n" +
        "  return rows.map(function(r){ return r.map(function(v){\n" +
        "    var t = v == null ? '' : String(v);\n" +
        "    if (/^[=+@-]/.test(t)) t = \"'\" + t;\n" +
        "    return t;\n" +
        "  }).join(','); }).join('\\n');\n" +
        "}\n" +
        "module.exports.toCsv = toCsv;\n",
    });
    try {
      const r = runRedteam(dir, ["safe.js"], LOCAL);
      assert.equal(r.exploits.filter((x) => x.attackClass === "csv-injection").length, 0, "a neutralised serialiser must not fire");
      assert.ok(r.lanes.some((l) => l.attackClass === "csv-injection" && l.live));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
