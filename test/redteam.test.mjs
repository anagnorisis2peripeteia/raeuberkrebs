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
