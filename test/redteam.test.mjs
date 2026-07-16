import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { runRedteam } from "../dist/runner.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = join(ROOT, "fixtures", "command-injection-node");
const LOCAL = { sandbox: { prefer: "local" } };

function scratch(files) {
  const dir = mkdtempSync(join(tmpdir(), "rk-test-"));
  writeFileSync(join(dir, "package.json"), '{"name":"s","version":"0.0.0","private":true,"type":"commonjs"}');
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
