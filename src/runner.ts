import { readdirSync } from "node:fs";
import { openSandbox, type SandboxOptions } from "./sandbox.js";
import type { Attacker } from "./attackers/attacker.js";
import { CommandInjectionAttacker } from "./attackers/command-injection.js";
import { CommandInjectionDotnetAttacker } from "./attackers/command-injection-dotnet.js";
import { CommandInjectionSwiftAttacker } from "./attackers/command-injection-swift.js";
import { PathTraversalSwiftAttacker } from "./attackers/path-traversal-swift.js";
import { PathTraversalAttacker } from "./attackers/path-traversal.js";
import { SsrfSwiftAttacker } from "./attackers/ssrf-swift.js";
import { SsrfAttacker } from "./attackers/ssrf.js";
import { CsvInjectionAttacker } from "./attackers/csv-injection.js";
import { BrokenAccessControlAttacker } from "./attackers/broken-access-control.js";
import { BrokenObjectAccessAttacker } from "./attackers/broken-object-access.js";
import { MissingAuthenticationAttacker } from "./attackers/missing-authentication.js";
import { ResourceExhaustionAttacker } from "./attackers/resource-exhaustion.js";
import { PrototypePollutionAttacker } from "./attackers/prototype-pollution.js";
import { ZipSlipAttacker } from "./attackers/zip-slip.js";
import { SsrfDotnetAttacker } from "./attackers/ssrf-dotnet.js";
import { PathTraversalDotnetAttacker } from "./attackers/path-traversal-dotnet.js";
import { UnsafeDeserializationDotnetAttacker } from "./attackers/unsafe-deserialization-dotnet.js";
import {
  MissingAuthenticationDotnetAttacker,
  ResourceExhaustionDotnetAttacker,
  UnsafeExecDotnetAttacker,
  BrokenObjectAccessDotnetAttacker,
  SqlInjectionDotnetAttacker,
  CsvInjectionDotnetAttacker,
  InsecureTlsDotnetAttacker,
  WeakCryptoDotnetAttacker,
  XxeDotnetAttacker,
  InsecureTempFileDotnetAttacker,
  ZipSlipDotnetAttacker,
  WebViewInjectionDotnetAttacker,
  WeakRandomDotnetAttacker,
  ArgumentInjectionDotnetAttacker,
  ToctouDotnetAttacker,
} from "./attackers/dotnet-more-lanes.js";
import type { Exploit, LaneStatus, RaeuberResult, Verdict } from "./types.js";

/** The registered attack lanes (Node + .NET). */
export const ATTACKERS: Attacker[] = [
  new CommandInjectionAttacker(),
  new CommandInjectionDotnetAttacker(),
  new CommandInjectionSwiftAttacker(),
  new PathTraversalSwiftAttacker(),
  new PathTraversalAttacker(),
  new SsrfSwiftAttacker(),
  new SsrfAttacker(),
  new CsvInjectionAttacker(),
  new BrokenAccessControlAttacker(),
  new BrokenObjectAccessAttacker(),
  new MissingAuthenticationAttacker(),
  new ResourceExhaustionAttacker(),
  new PrototypePollutionAttacker(),
  new ZipSlipAttacker(),
  // C# (.NET) static lanes — feed the sweep's guard-consistency signal for the Windows node; the
  // execute-gate skips them (staticOnly), so proof is per-lead. Command-injection has its own
  // drive-and-prove .NET lane above (CommandInjectionDotnetAttacker).
  new SsrfDotnetAttacker(),
  new PathTraversalDotnetAttacker(),
  new UnsafeDeserializationDotnetAttacker(),
  MissingAuthenticationDotnetAttacker,
  ResourceExhaustionDotnetAttacker,
  UnsafeExecDotnetAttacker,
  BrokenObjectAccessDotnetAttacker,
  SqlInjectionDotnetAttacker,
  CsvInjectionDotnetAttacker,
  // Round-2 breadth lanes: new sink families (TLS-downgrade, weak crypto, XXE, insecure temp,
  // C# zip-slip, WebView script-injection). All staticOnly — they feed the sweep, not the gate.
  InsecureTlsDotnetAttacker,
  WeakCryptoDotnetAttacker,
  XxeDotnetAttacker,
  InsecureTempFileDotnetAttacker,
  ZipSlipDotnetAttacker,
  WebViewInjectionDotnetAttacker,
  // Round-3 lanes: weak-random (security RNG), argument-injection (process args), TOCTOU.
  WeakRandomDotnetAttacker,
  ArgumentInjectionDotnetAttacker,
  ToctouDotnetAttacker,
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

  const applicable = ATTACKERS.filter(
    (a) => !a.staticOnly && changedFiles.some((f) => a.handles(f)),
  );
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
