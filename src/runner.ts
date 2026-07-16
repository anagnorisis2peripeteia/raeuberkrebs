import { readdirSync } from "node:fs";
import { openSandbox, type SandboxOptions } from "./sandbox.js";
import type { Attacker } from "./attackers/attacker.js";
import { CommandInjectionAttacker } from "./attackers/command-injection.js";
import { PathTraversalAttacker } from "./attackers/path-traversal.js";
import { SsrfAttacker } from "./attackers/ssrf.js";
import { CsvInjectionAttacker } from "./attackers/csv-injection.js";
import type { Exploit, LaneStatus, RaeuberResult, Verdict } from "./types.js";

/** The registered attack lanes (Node). */
export const ATTACKERS: Attacker[] = [
  new CommandInjectionAttacker(),
  new PathTraversalAttacker(),
  new SsrfAttacker(),
  new CsvInjectionAttacker(),
];

function verdictFrom(lanes: LaneStatus[], exploits: Exploit[]): Verdict {
  if (exploits.length > 0) return "vulnerable";
  const anyDead = lanes.some((l) => !l.live);
  if (anyDead) return "lane-dead"; // an applicable lane could not prove itself → fail-closed
  const anyAttacked = lanes.some((l) => l.attacked > 0);
  if (!anyAttacked) return "insufficient"; // nothing on the changed surface could be driven
  return "clean";
}

/** Files in `dir` this attacker handles (used to drive its planted-fixture canary). */
function handledFilesIn(dir: string, attacker: Attacker): string[] {
  return readdirSync(dir).filter((f) => attacker.handles(f));
}

/**
 * Prove a lane is LIVE: open a sandbox over the lane's planted-vulnerable fixture and attack it. A
 * live lane MUST produce at least one exploit against its own planted vuln, else it is quarantined
 * (the family's "caught its own planted defect or it's dead" rule). Returns the sandbox identity
 * used, for the evidence trail.
 */
function proveLaneLive(
  attacker: Attacker,
  sbox: SandboxOptions,
): { live: boolean; reason?: string; sandbox: string } {
  const box = openSandbox(attacker.canaryFixtureDir, sbox);
  try {
    const files = handledFilesIn(attacker.canaryFixtureDir, attacker);
    const fired = attacker.hunt(attacker.canaryFixtureDir, files, box);
    return fired.length > 0
      ? { live: true, sandbox: box.name }
      : {
          live: false,
          reason: `command-injection canary did not fire against its planted fixture (${box.name})`,
          sandbox: box.name,
        };
  } catch (err) {
    return { live: false, reason: `canary errored: ${err instanceof Error ? err.message : err}`, sandbox: box.name };
  } finally {
    box.dispose();
  }
}

export interface RunOptions {
  sandbox?: SandboxOptions;
}

/**
 * Attack the changed surface. For each lane applicable to `changedFiles`: prove it live against its
 * fixture, and if live, hunt the target inside a sandbox opened over a throwaway COPY of `targetDir`
 * (the user's tree is never mutated; a fired PoC ran in isolation). Fails closed on any dead lane.
 */
export function runRedteam(
  targetDir: string,
  changedFiles: string[],
  opts: RunOptions = {},
): RaeuberResult {
  const started = Date.now();
  const sbox = opts.sandbox ?? {};
  const lanes: LaneStatus[] = [];
  const exploits: Exploit[] = [];
  let sandboxName = "none";

  const applicable = ATTACKERS.filter((a) => changedFiles.some((f) => a.handles(f)));
  if (applicable.length === 0) {
    return {
      verdict: "clean",
      exploits: [],
      lanes: [],
      sandbox: "none",
      error: "no changed file matches an attack lane — nothing to red-team",
      elapsedMs: Date.now() - started,
    };
  }

  for (const attacker of applicable) {
    const liveness = proveLaneLive(attacker, sbox);
    sandboxName = liveness.sandbox;
    if (!liveness.live) {
      lanes.push({ attackClass: attacker.attackClass, live: false, attacked: 0, fired: 0, deadReason: liveness.reason });
      continue;
    }
    const targetFiles = changedFiles.filter((f) => attacker.handles(f));
    const box = openSandbox(targetDir, sbox);
    let laneExploits: Exploit[] = [];
    try {
      laneExploits = attacker.hunt(targetDir, targetFiles, box);
    } finally {
      box.dispose();
    }
    exploits.push(...laneExploits);
    lanes.push({
      attackClass: attacker.attackClass,
      live: true,
      attacked: targetFiles.length,
      fired: laneExploits.length,
    });
  }

  const verdict = verdictFrom(lanes, exploits);
  return {
    verdict,
    exploits,
    lanes,
    sandbox: sandboxName,
    error:
      verdict === "lane-dead"
        ? lanes.find((l) => !l.live)?.deadReason ?? "an attack lane could not be proven live"
        : verdict === "insufficient"
          ? "no changed entrypoint could be driven with adversarial input"
          : null,
    elapsedMs: Date.now() - started,
  };
}
