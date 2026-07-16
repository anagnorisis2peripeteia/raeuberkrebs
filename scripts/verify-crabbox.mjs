// Exercises the HARDENED path: open a real crabbox (apple-container) lease per lane and prove the
// lane fires its planted exploit INSIDE genuine Linux-container isolation (not the local fallback).
// Fails non-zero if crabbox is unavailable or any lane does not fire in an isolated box — this is
// the "the isolated path may only be claimed once it fires against a real lease" gate.
import { openSandbox } from "../dist/sandbox.js";
import { CommandInjectionAttacker } from "../dist/attackers/command-injection.js";
import { PathTraversalAttacker } from "../dist/attackers/path-traversal.js";
import { SsrfAttacker } from "../dist/attackers/ssrf.js";

const LANES = [
  { attacker: new CommandInjectionAttacker(), file: "vuln.js", proof: "marker-executed" },
  { attacker: new PathTraversalAttacker(), file: "vuln.js", proof: "secret-exfiltrated" },
  { attacker: new SsrfAttacker(), file: "vuln.js", proof: "oob-request" },
];

let failed = 0;
for (const { attacker, file, proof } of LANES) {
  const label = attacker.attackClass;
  let box;
  try {
    box = openSandbox(attacker.canaryFixtureDir, { prefer: "crabbox" });
  } catch (err) {
    console.log(`[crabbox:${label}] LEASE FAILED — ${err?.message ?? err}`);
    failed++;
    continue;
  }
  try {
    if (!box.isolated) {
      console.log(`[crabbox:${label}] NOT ISOLATED — got sandbox '${box.name}', refusing to claim isolation`);
      failed++;
      continue;
    }
    const exploits = attacker.hunt(attacker.canaryFixtureDir, [file], box);
    const e = exploits.find((x) => x.attackClass === label);
    if (e && e.proof === proof) {
      console.log(`[crabbox:${label}] FIRED in ${box.name} — ${e.attackClass}@${e.file}:${e.line} proof=${e.proof}`);
      console.log(`   evidence: ${e.evidence.split("\n")[0]}`);
    } else {
      console.log(`[crabbox:${label}] DID NOT FIRE in ${box.name} (exploits=${exploits.length})`);
      failed++;
    }
  } finally {
    box.dispose();
  }
}

if (failed > 0) {
  console.log(`\ncrabbox verification FAILED: ${failed} lane(s) did not fire in an isolated box`);
  process.exit(1);
}
console.log("\ncrabbox verification PASS: every lane fired inside real Linux-container isolation");
