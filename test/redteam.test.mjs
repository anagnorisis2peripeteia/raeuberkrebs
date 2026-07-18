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
import { BrokenAccessControlAttacker } from "../dist/attackers/broken-access-control.js";
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

const PT_SWIFT_FIXTURE = join(ROOT, "fixtures", "path-traversal-swift");

describe("raeuberkrebs path-traversal gate (Swift lane)", () => {
  it("fires on the planted Swift fixture — reads a decoy via ../ (secret-exfiltrated)", () => {
    const r = runRedteam(PT_SWIFT_FIXTURE, ["vuln.swift"], LOCAL);
    assert.equal(r.verdict, "vulnerable");
    assert.equal(r.exploits.length, 1);
    const e = r.exploits[0];
    assert.equal(e.attackClass, "path-traversal");
    assert.equal(e.proof, "secret-exfiltrated");
    assert.match(e.evidence, /RAEUBER_[0-9a-f]+_TRAVERSAL_SECRET/);
  });

  it("does NOT fire on a safe fixed-path read (no false positive)", () => {
    const dir = scratch({
      "safe.swift": [
        "import Foundation",
        "func readNotes(_ name: String) -> String {",
        "  _ = name",
        '  return (try? String(contentsOfFile: "/etc/hostname", encoding: .utf8)) ?? ""',
        "}",
      ].join("\n"),
    });
    try {
      const r = runRedteam(dir, ["safe.swift"], LOCAL);
      assert.equal(r.exploits.length, 0);
      assert.notEqual(r.verdict, "vulnerable");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

const SSRF_SWIFT_FIXTURE = join(ROOT, "fixtures", "ssrf-swift");

describe("raeuberkrebs ssrf gate (Swift lane)", () => {
  it("fires on the planted Swift fixture — fetches a loopback URL (oob-request)", () => {
    const r = runRedteam(SSRF_SWIFT_FIXTURE, ["vuln.swift"], LOCAL);
    assert.equal(r.verdict, "vulnerable");
    assert.equal(r.exploits.length, 1);
    const e = r.exploits[0];
    assert.equal(e.attackClass, "ssrf");
    assert.equal(e.proof, "oob-request");
    assert.match(e.evidence, /RAEUBER_[0-9a-f]+/); // the marker the in-sandbox listener observed
  });

  it("does NOT fire on a fetch of a fixed-literal URL (no false positive)", () => {
    const dir = scratch({
      "safe.swift": [
        "import Foundation",
        "func probe(_ ignored: String) -> String {",
        "  _ = ignored",
        '  guard let url = URL(string: "http://127.0.0.1:9/fixed") else { return "" }',
        "  let sema = DispatchSemaphore(value: 0)",
        "  URLSession.shared.dataTask(with: url) { _, _, _ in sema.signal() }.resume()",
        "  _ = sema.wait(timeout: .now() + 1)",
        '  return ""',
        "}",
      ].join("\n"),
    });
    try {
      const r = runRedteam(dir, ["safe.swift"], LOCAL);
      assert.equal(r.exploits.length, 0);
      assert.notEqual(r.verdict, "vulnerable");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

const REDOS_SWIFT_FIXTURE = join(ROOT, "fixtures", "resource-exhaustion-swift");

describe("raeuberkrebs resource-exhaustion gate (Swift lane)", () => {
  it("fires on the planted Swift fixture — a catastrophic regex hangs on a crafted input (input-caused-hang)", () => {
    const r = runRedteam(REDOS_SWIFT_FIXTURE, ["vuln.swift"], LOCAL);
    assert.equal(r.verdict, "vulnerable");
    assert.equal(r.exploits.length, 1);
    const e = r.exploits[0];
    assert.equal(e.attackClass, "resource-exhaustion");
    assert.equal(e.proof, "input-caused-hang");
    assert.match(e.evidence, /BENIGN_OK/);
  });

  it("does NOT fire on a linear (anchored) regex (no false positive)", () => {
    const dir = scratch({
      "safe.swift": [
        "import Foundation",
        "func parseVersion(_ raw: String) -> Int {",
        '  let pattern = #"^[0-9]+(?:\\.[0-9]+)*$"#',
        "  guard let re = try? NSRegularExpression(pattern: pattern) else { return 0 }",
        "  let r = NSRange(raw.startIndex..<raw.endIndex, in: raw)",
        "  return re.matches(in: raw, options: [], range: r).count",
        "}",
      ].join("\n"),
    });
    try {
      const r = runRedteam(dir, ["safe.swift"], LOCAL);
      assert.equal(r.exploits.length, 0);
      assert.notEqual(r.verdict, "vulnerable");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

const SQLI_SWIFT_FIXTURE = join(ROOT, "fixtures", "sql-injection-swift");

describe("raeuberkrebs sql-injection gate (Swift lane)", () => {
  it("fires on the planted Swift fixture — an OR '1'='1 payload bypasses WHERE (secret-exfiltrated)", () => {
    const r = runRedteam(SQLI_SWIFT_FIXTURE, ["vuln.swift"], LOCAL);
    assert.equal(r.verdict, "vulnerable");
    assert.equal(r.exploits.length, 1);
    assert.equal(r.exploits[0].attackClass, "sql-injection");
    assert.equal(r.exploits[0].proof, "secret-exfiltrated");
  });

  it("does NOT fire on a parameterized query (no false positive)", () => {
    const dir = scratch({
      "safe.swift": [
        "import Foundation",
        "import SQLite3",
        "func lookup(_ name: String) -> String {",
        "  var db: OpaquePointer?",
        '  sqlite3_open(":memory:", &db)',
        "  sqlite3_exec(db, \"CREATE TABLE t(name TEXT, val TEXT)\", nil, nil, nil)",
        "  sqlite3_exec(db, \"INSERT INTO t VALUES('public','ok')\", nil, nil, nil)",
        "  sqlite3_exec(db, \"INSERT INTO t VALUES('secret','RAEUBER_sqli_row')\", nil, nil, nil)",
        "  var stmt: OpaquePointer?",
        "  var out = \"\"",
        '  if sqlite3_prepare_v2(db, "SELECT val FROM t WHERE name = ?", -1, &stmt, nil) == SQLITE_OK {',
        "    sqlite3_bind_text(stmt, 1, name, -1, nil)",
        "    while sqlite3_step(stmt) == SQLITE_ROW { if let c = sqlite3_column_text(stmt, 0) { out += String(cString: c) } }",
        "  }",
        "  sqlite3_finalize(stmt); sqlite3_close(db); return out",
        "}",
      ].join("\n"),
    });
    try {
      const r = runRedteam(dir, ["safe.swift"], LOCAL);
      assert.equal(r.exploits.length, 0);
      assert.notEqual(r.verdict, "vulnerable");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

const CSV_SWIFT_FIXTURE = join(ROOT, "fixtures", "csv-injection-swift");

describe("raeuberkrebs csv-injection gate (Swift lane)", () => {
  it("fires on the planted Swift fixture — a =<marker> cell survives un-neutralized (formula-unescaped)", () => {
    const r = runRedteam(CSV_SWIFT_FIXTURE, ["vuln.swift"], LOCAL);
    assert.equal(r.verdict, "vulnerable");
    assert.equal(r.exploits.length, 1);
    assert.equal(r.exploits[0].attackClass, "csv-injection");
    assert.equal(r.exploits[0].proof, "formula-unescaped");
  });

  it("does NOT fire when the cell is formula-prefix guarded (no false positive)", () => {
    const dir = scratch({
      "safe.swift": [
        "import Foundation",
        "func csvCell(_ value: String) -> String {",
        "  var v = value",
        '  if let f = v.first, "=+-@".contains(f) { v = "\x27" + v }',
        '  if v.contains(",") || v.contains("\"") { v = "\"" + v.replacingOccurrences(of: "\"", with: "\"\"") + "\"" }',
        '  return v + ",count"',
        "}",
      ].join("\n"),
    });
    try {
      const r = runRedteam(dir, ["safe.swift"], LOCAL);
      assert.equal(r.exploits.length, 0);
      assert.notEqual(r.verdict, "vulnerable");
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

const BAC_FIXTURE = join(ROOT, "fixtures", "broken-access-control-node");

describe("raeuberkrebs broken-access-control gate (models the openclaw GHSA-j4mm privilege-escalation)", () => {
  it("fires on the planted differential — a WRITE path reaches an ADMIN-gated effect (privilege-escalated)", () => {
    const r = runRedteam(BAC_FIXTURE, ["vuln.js"], LOCAL);
    assert.equal(r.verdict, "vulnerable");
    const e = r.exploits.find((x) => x.attackClass === "broken-access-control");
    assert.ok(e, "expected a broken-access-control exploit");
    assert.equal(e.proof, "privilege-escalated");
    assert.match(e.sink, /authz-differential\(applySetting\)/);
    assert.match(e.summary, /createSetting/);
    assert.match(e.summary, /patchSetting/);
  });

  it("fires on NOVEL differential code — an EDITOR path reaches an ADMIN-gated effect (generalizes)", () => {
    const dir = scratch({
      "acl.js":
        "const state = {};\n" +
        "function persist(v){ state.v = v; return { v: state.v }; }\n" +
        "function editItem(ctx, v){ if (!ctx || !ctx.scopes.includes('editor')) throw new Error('forbidden: editor scope required'); return persist(v); }\n" +
        "function adminItem(ctx, v){ if (!ctx || !ctx.scopes.includes('admin')) throw new Error('forbidden: admin scope required'); return persist(v); }\n" +
        "module.exports.editItem = editItem;\n" +
        "module.exports.adminItem = adminItem;\n",
    });
    try {
      const r = runRedteam(dir, ["acl.js"], LOCAL);
      assert.equal(r.verdict, "vulnerable");
      const e = r.exploits.find((x) => x.attackClass === "broken-access-control");
      assert.ok(e, "expected a broken-access-control exploit on novel code");
      assert.equal(e.proof, "privilege-escalated");
      assert.match(e.sink, /authz-differential\(persist\)/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does NOT fire when both entrypoints enforce the SAME scope (no differential)", () => {
    const dir = scratch({
      "same.js":
        "const s = {};\n" +
        "function a(ctx, v){ if (!ctx || !ctx.scopes.includes('admin')) throw new Error('admin required'); s.v = v; return s.v; }\n" +
        "function b(ctx, v){ if (!ctx || !ctx.scopes.includes('admin')) throw new Error('admin required'); s.v = v; return s.v; }\n" +
        "module.exports.a = a;\nmodule.exports.b = b;\n",
    });
    try {
      const r = runRedteam(dir, ["same.js"], LOCAL);
      assert.equal(r.exploits.filter((x) => x.attackClass === "broken-access-control").length, 0, "equal guards on the same effect is not an escalation");
      assert.ok(r.lanes.some((l) => l.attackClass === "broken-access-control" && l.live));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does NOT fire when the weaker path reaches a DIFFERENT effect (no shared sink)", () => {
    const dir = scratch({
      "distinct.js":
        "const s = {};\n" +
        "function readItem(ctx){ if (!ctx || !ctx.scopes.includes('read')) throw new Error('read required'); return s.value; }\n" +
        "function adminWrite(ctx, v){ if (!ctx || !ctx.scopes.includes('admin')) throw new Error('admin required'); s.value = v; return s.value; }\n" +
        "module.exports.readItem = readItem;\nmodule.exports.adminWrite = adminWrite;\n",
    });
    try {
      const r = runRedteam(dir, ["distinct.js"], LOCAL);
      assert.equal(r.exploits.filter((x) => x.attackClass === "broken-access-control").length, 0, "different effects share no sink → no differential");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("fires on a BURIED differential — write reaches an admin effect through an internal helper chain (inter-procedural)", () => {
    const dir = scratch({
      "buried.js":
        "const s = {};\n" +
        "function reallyApply(v){ s.v = v; return { v: s.v }; }\n" + // the real privileged effect
        "function helper(v){ return reallyApply(v); }\n" + // an internal hop
        "function writeThing(ctx, v){ if (!ctx || !ctx.scopes.includes('write')) throw new Error('write required'); return helper(v); }\n" + // write -> helper -> reallyApply
        "function adminThing(ctx, v){ if (!ctx || !ctx.scopes.includes('admin')) throw new Error('admin required'); return reallyApply(v); }\n" + // admin -> reallyApply direct
        "module.exports.writeThing = writeThing;\nmodule.exports.adminThing = adminThing;\n",
    });
    try {
      const r = runRedteam(dir, ["buried.js"], LOCAL);
      assert.equal(r.verdict, "vulnerable", "inter-procedural closure should reach the buried shared effect");
      const e = r.exploits.find((x) => x.attackClass === "broken-access-control");
      assert.ok(e, "expected a buried broken-access-control exploit");
      assert.match(e.sink, /authz-differential\(reallyApply\)/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does NOT fire on a shared HARNESS wrapper (callback passthrough is not a shared effect) — issue #23", () => {
    const dir = scratch({
      "harness.js":
        "const s = {};\n" +
        "function runWorkspace(params){ return params.run(); }\n" + // harness: delegates to caller's callback
        "function readOne(ctx){ if (!ctx || !ctx.scopes.includes('read')) throw new Error('read required'); return runWorkspace({ run: () => s.x }); }\n" +
        "function adminMutate(ctx, v){ if (!ctx || !ctx.scopes.includes('admin')) throw new Error('admin required'); return runWorkspace({ run: () => { s.x = v; return s.x; } }); }\n" +
        "module.exports.readOne = readOne;\nmodule.exports.adminMutate = adminMutate;\n",
    });
    try {
      const r = runRedteam(dir, ["harness.js"], LOCAL);
      assert.equal(r.exploits.filter((x) => x.attackClass === "broken-access-control").length, 0, "a shared harness wrapper is plumbing, not a shared effect");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("bac staticLeads surfaces authorization-decision lines as the differential lead surface", () => {
    const bac = new BrokenAccessControlAttacker();
    const leads = bac.staticLeads(
      "export function create(ctx){ if (!ctx.scopes.includes('write')) throw 0; return apply(); }\n" +
        "export function patch(ctx){ if (!ctx.scopes.includes('admin')) throw 0; return apply(); }\n",
    );
    assert.ok(leads.length >= 2, "each scope-check line is an authz lead");
  });
});

const BOA_FIXTURE = join(ROOT, "fixtures", "broken-object-access-node");

describe("raeuberkrebs broken-object-access gate (IDOR / CWE-639 — object-level authorization)", () => {
  it("fires on the planted IDOR — one identity reads another's object by id (foreign-object-accessed)", () => {
    const r = runRedteam(BOA_FIXTURE, ["vuln.js"], LOCAL);
    assert.equal(r.verdict, "vulnerable");
    const e = r.exploits.find((x) => x.attackClass === "broken-object-access");
    assert.ok(e, "expected a broken-object-access exploit");
    assert.equal(e.proof, "foreign-object-accessed");
    assert.match(e.sink, /object-access\(getDoc\)/);
  });

  it("fires on NOVEL IDOR code — differently-named create/fetch pair (generalizes)", () => {
    const dir = scratch({
      "store.js":
        "const records = {}; let n = 0;\n" +
        "function addRecord(ctx, data){ const key = 'r' + (++n); records[key] = { owner: ctx.userId, data }; return { key }; }\n" +
        "function fetchRecord(ctx, key){ const r = records[key]; if (!r) throw new Error('missing'); return { key, data: r.data }; }\n" + // no ownership check
        "module.exports.addRecord = addRecord;\nmodule.exports.fetchRecord = fetchRecord;\n",
    });
    try {
      const r = runRedteam(dir, ["store.js"], LOCAL);
      assert.equal(r.verdict, "vulnerable");
      const e = r.exploits.find((x) => x.attackClass === "broken-object-access");
      assert.ok(e, "expected an IDOR exploit on novel code");
      assert.match(e.sink, /object-access\(fetchRecord\)/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does NOT fire when the reader enforces ownership (owner check present)", () => {
    const dir = scratch({
      "safe.js":
        "const items = {}; let n = 0;\n" +
        "function createItem(ctx, data){ const id = 'i' + (++n); items[id] = { owner: ctx.identity, data }; return { id }; }\n" +
        "function getItem(ctx, id){ const it = items[id]; if (!it) throw new Error('missing'); if (it.owner !== ctx.identity) throw new Error('forbidden: not owner'); return { id, data: it.data }; }\n" +
        "module.exports.createItem = createItem;\nmodule.exports.getItem = getItem;\n",
    });
    try {
      const r = runRedteam(dir, ["safe.js"], LOCAL);
      assert.equal(r.exploits.filter((x) => x.attackClass === "broken-object-access").length, 0, "an ownership-checked reader must not fire");
      assert.ok(r.lanes.some((l) => l.attackClass === "broken-object-access" && l.live));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

const NOAUTH_FIXTURE = join(ROOT, "fixtures", "missing-authentication-node");

describe("raeuberkrebs missing-authentication gate (webhook/ingress — CWE-306/290)", () => {
  it("fires on a webhook that dispatches without a signature check (unauthenticated-action)", () => {
    const r = runRedteam(NOAUTH_FIXTURE, ["vuln.js"], LOCAL);
    assert.equal(r.verdict, "vulnerable");
    const e = r.exploits.find((x) => x.attackClass === "missing-authentication");
    assert.ok(e, "expected a missing-authentication exploit");
    assert.equal(e.proof, "unauthenticated-action");
    assert.match(e.sink, /ingress\(handleWebhook\)/);
  });

  it("fires on NOVEL ingress code — onUpdate dispatches with no auth (generalizes)", () => {
    const dir = scratch({
      "bot.js":
        "const store = {};\n" +
        "function applyConfig(c){ store.cfg = c; return { applied: c }; }\n" +
        "function onUpdate(update){ const cmd = update && update.message && update.message.text; return applyConfig(cmd); }\n" +
        "module.exports.onUpdate = onUpdate;\n",
    });
    try {
      const r = runRedteam(dir, ["bot.js"], LOCAL);
      assert.equal(r.verdict, "vulnerable");
      const e = r.exploits.find((x) => x.attackClass === "missing-authentication");
      assert.ok(e, "expected a missing-authentication exploit on novel ingress code");
      assert.match(e.sink, /ingress\(onUpdate\)/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does NOT fire when the handler verifies the request signature", () => {
    const dir = scratch({
      "secure.js":
        "function verifySignature(req){ const s = req.headers && req.headers['x-signature']; return s === 'valid-sig'; }\n" +
        "function dispatch(cmd){ return { done: cmd }; }\n" +
        "function onWebhook(req){ if (!verifySignature(req)) throw new Error('unauthorized: bad signature'); return dispatch(req.body && req.body.action); }\n" +
        "module.exports.onWebhook = onWebhook;\n",
    });
    try {
      const r = runRedteam(dir, ["secure.js"], LOCAL);
      assert.equal(r.exploits.filter((x) => x.attackClass === "missing-authentication").length, 0, "a signature-verified handler must not fire");
      assert.ok(r.lanes.some((l) => l.attackClass === "missing-authentication" && l.live));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

const REDOS_FIXTURE = join(ROOT, "fixtures", "resource-exhaustion-node");

describe("raeuberkrebs resource-exhaustion gate (ReDoS — CWE-400/1333)", () => {
  it("fires on a catastrophic-backtracking regex applied to input (input-caused-hang)", () => {
    const r = runRedteam(REDOS_FIXTURE, ["vuln.js"], LOCAL);
    assert.equal(r.verdict, "vulnerable");
    const e = r.exploits.find((x) => x.attackClass === "resource-exhaustion");
    assert.ok(e, "expected a resource-exhaustion exploit");
    assert.equal(e.proof, "input-caused-hang");
    assert.equal(e.sink, "catastrophic-regex");
  });

  it("fires on NOVEL ReDoS code — a different nested-quantifier regex (generalizes)", () => {
    const dir = scratch({
      "email.js":
        "function isEmail(s){ return /^([a-zA-Z0-9]+)*@example\\.com$/.test(s); }\n" +
        "module.exports.isEmail = isEmail;\n",
    });
    try {
      const r = runRedteam(dir, ["email.js"], LOCAL);
      assert.equal(r.verdict, "vulnerable");
      assert.ok(r.exploits.some((x) => x.attackClass === "resource-exhaustion"), "expected a ReDoS exploit on novel code");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does NOT fire on a linear (safe) regex — no catastrophic backtracking", () => {
    const dir = scratch({
      "slug.js":
        "function isSlug(s){ return /^[a-z0-9-]+$/.test(s); }\n" +
        "module.exports.isSlug = isSlug;\n",
    });
    try {
      const r = runRedteam(dir, ["slug.js"], LOCAL);
      assert.equal(r.exploits.filter((x) => x.attackClass === "resource-exhaustion").length, 0, "a linear regex must not fire");
      assert.ok(r.lanes.some((l) => l.attackClass === "resource-exhaustion" && l.live));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

const PROTO_FIXTURE = join(ROOT, "fixtures", "prototype-pollution-node");

describe("raeuberkrebs prototype-pollution gate (CWE-1321)", () => {
  it("fires on a recursive merge with no __proto__ guard (prototype-polluted)", () => {
    const r = runRedteam(PROTO_FIXTURE, ["vuln.js"], LOCAL);
    assert.equal(r.verdict, "vulnerable");
    const e = r.exploits.find((x) => x.attackClass === "prototype-pollution");
    assert.ok(e, "expected a prototype-pollution exploit");
    assert.equal(e.proof, "prototype-polluted");
    assert.match(e.sink, /merge-sink\(deepMerge\)/);
  });

  it("fires on NOVEL code — a path-set helper (setPath) via __proto__.x (generalizes)", () => {
    const dir = scratch({
      "conf.js":
        "function setPath(obj, path, val){ const keys = Array.isArray(path) ? path : String(path).split('.'); let o = obj; for (let i = 0; i < keys.length - 1; i++){ const k = keys[i]; if (o[k] == null || typeof o[k] !== 'object') o[k] = {}; o = o[k]; } o[keys[keys.length - 1]] = val; return obj; }\n" +
        "module.exports.setPath = setPath;\n",
    });
    try {
      const r = runRedteam(dir, ["conf.js"], LOCAL);
      assert.equal(r.verdict, "vulnerable");
      assert.ok(r.exploits.some((x) => x.attackClass === "prototype-pollution"), "expected a pollution exploit on the path-set helper");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does NOT fire when the merge skips __proto__/constructor/prototype", () => {
    const dir = scratch({
      "safe.js":
        "function safeMerge(target, src){ for (const key in src){ if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue; const v = src[key]; if (v && typeof v === 'object' && target[key] && typeof target[key] === 'object') safeMerge(target[key], v); else target[key] = v; } return target; }\n" +
        "module.exports.safeMerge = safeMerge;\n",
    });
    try {
      const r = runRedteam(dir, ["safe.js"], LOCAL);
      assert.equal(r.exploits.filter((x) => x.attackClass === "prototype-pollution").length, 0, "a key-guarded merge must not pollute");
      assert.ok(r.lanes.some((l) => l.attackClass === "prototype-pollution" && l.live));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

const ZIPSLIP_FIXTURE = join(ROOT, "fixtures", "zip-slip-node");

describe("raeuberkrebs zip-slip gate (archive extraction path traversal — CWE-22)", () => {
  it("fires when an extractor writes a ../ entry outside the target dir (extraction-escaped)", () => {
    const r = runRedteam(ZIPSLIP_FIXTURE, ["vuln.js"], LOCAL);
    assert.equal(r.verdict, "vulnerable");
    const e = r.exploits.find((x) => x.attackClass === "zip-slip");
    assert.ok(e, "expected a zip-slip exploit");
    assert.equal(e.proof, "extraction-escaped");
    assert.match(e.sink, /archive-extract\(extractEntries\)/);
  });

  it("fires on NOVEL code — a differently-named unpack helper (generalizes)", () => {
    const dir = scratch({
      "unpack.js":
        "const fs = require('fs'); const path = require('path');\n" +
        "function unpackArchive(entries, dir){ fs.mkdirSync(dir, { recursive: true }); for (const e of entries){ const d = path.join(dir, e.path); fs.mkdirSync(path.dirname(d), { recursive: true }); fs.writeFileSync(d, e.content); } }\n" +
        "module.exports.unpackArchive = unpackArchive;\n",
    });
    try {
      const r = runRedteam(dir, ["unpack.js"], LOCAL);
      assert.equal(r.verdict, "vulnerable");
      assert.ok(r.exploits.some((x) => x.attackClass === "zip-slip"), "expected a zip-slip exploit on novel extractor");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does NOT fire when the extractor containment-checks each entry", () => {
    const dir = scratch({
      "safe.js":
        "const fs = require('fs'); const path = require('path');\n" +
        "function extractSafe(entries, dir){ const root = path.resolve(dir); fs.mkdirSync(root, { recursive: true }); for (const e of entries){ const d = path.resolve(root, e.name); if (d !== root && !d.startsWith(root + path.sep)) throw new Error('blocked: ' + e.name); fs.mkdirSync(path.dirname(d), { recursive: true }); fs.writeFileSync(d, e.data); } }\n" +
        "module.exports.extractSafe = extractSafe;\n",
    });
    try {
      const r = runRedteam(dir, ["safe.js"], LOCAL);
      assert.equal(r.exploits.filter((x) => x.attackClass === "zip-slip").length, 0, "a containment-checked extractor must not escape");
      assert.ok(r.lanes.some((l) => l.attackClass === "zip-slip" && l.live));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
