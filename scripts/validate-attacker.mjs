#!/usr/bin/env node
// Prove every attack lane is LIVE: each must exploit its own planted-vulnerable fixture. A lane
// that cannot fire against a known vuln would silently pass real vulnerable code — the family's
// cardinal fail-open — so it is quarantined and this exits non-zero. Local sandbox by default (the
// PoCs are benign); pass nothing special — this is the canary, not a target attack.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { ATTACKERS } from "../dist/runner.js";
import { openSandbox } from "../dist/sandbox.js";

let ok = true;
for (const attacker of ATTACKERS) {
  if (!attacker.canaryFixtureDir) {
    if (attacker.staticOnly) {
      console.error(`[validate:${attacker.attackClass}] SKIP (static-only lane) — no canary fixture dir configured.`);
      continue;
    }
    console.error(
      `[validate:${attacker.attackClass}] DEAD — no canary fixture dir configured. ` +
        `Quarantined: set canaryFixtureDir or remove this lane from validate scope.`,
    );
    ok = false;
    continue;
  }

  const fixtureDir = attacker.canaryFixtureDir;
  if (!existsSync(fixtureDir)) {
    console.error(`[validate:${attacker.attackClass}] DEAD — canary fixture dir missing: ${fixtureDir}`);
    ok = false;
    continue;
  }

  let files = [];
  try {
    files = readdirSync(fixtureDir).filter((f) => attacker.handles(f));
  } catch {
    console.error(
      `[validate:${attacker.attackClass}] DEAD — canary fixture dir missing (${fixtureDir}). ` +
        `Quarantined: fix fixture path before this lane can gate real code.`,
    );
    ok = false;
    continue;
  }

  if (files.length === 0) {
    console.error(`[validate:${attacker.attackClass}] DEAD — no canary fixture files matched this lane`);
    ok = false;
    continue;
  }

  if (attacker.staticOnly) {
    const leads = files.flatMap((file) => attacker.staticLeads(readFileSync(join(fixtureDir, file), "utf8")));
    if (leads.length > 0) {
      console.error(`[validate:${attacker.attackClass}] LIVE (static) — ${leads.length} lead(s) matched canary fixture`);
      continue;
    }
    console.error(`[validate:${attacker.attackClass}] DEAD — static canary did not match lane sink shape`);
    ok = false;
    continue;
  }

  const box = openSandbox(fixtureDir, { prefer: "local" });
  let exploits = [];
  try {
    exploits = attacker.hunt(fixtureDir, files, box);
  } finally {
    box.dispose();
  }
  if (exploits.length > 0) {
    console.error(
      `[validate:${attacker.attackClass}] LIVE — fired ${exploits.length} exploit(s) on its planted fixture ` +
        `(e.g. ${exploits[0].file}:${exploits[0].line} via ${exploits[0].sink}); sandbox=${box.name}`,
    );
  } else {
    console.error(
      `[validate:${attacker.attackClass}] DEAD — did not fire against its planted fixture. ` +
        `Quarantined: fix the lane before it can gate real code.`,
    );
    ok = false;
  }
}
process.exit(ok ? 0 : 1);
