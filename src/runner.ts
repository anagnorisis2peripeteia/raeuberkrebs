import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { openSandbox, type Sandbox, type SandboxOptions } from "./sandbox.js";
import type { Attacker } from "./attackers/attacker.js";
import { CommandInjectionAttacker } from "./attackers/command-injection.js";
import { CommandInjectionDotnetAttacker } from "./attackers/command-injection-dotnet.js";
import { CommandInjectionGoAttacker } from "./attackers/command-injection-go.js";
import { CommandInjectionSwiftAttacker } from "./attackers/command-injection-swift.js";
import { CommandInjectionPythonAttacker } from "./attackers/command-injection-python.js";
import { PathTraversalSwiftAttacker } from "./attackers/path-traversal-swift.js";
import { DifferentialOracleSwiftAttacker } from "./attackers/differential-oracle-swift.js";
import { PathTraversalAttacker } from "./attackers/path-traversal.js";
import { PathTraversalGoAttacker } from "./attackers/path-traversal-go.js";
import { PathTraversalPythonAttacker } from "./attackers/path-traversal-python.js";
import { SsrfSwiftAttacker } from "./attackers/ssrf-swift.js";
import { ResourceExhaustionSwiftAttacker } from "./attackers/resource-exhaustion-swift.js";
import { SqlInjectionSwiftAttacker } from "./attackers/sql-injection-swift.js";
import { CsvInjectionSwiftAttacker } from "./attackers/csv-injection-swift.js";
import { SsrfAttacker } from "./attackers/ssrf.js";
import { CsvInjectionAttacker } from "./attackers/csv-injection.js";
import { BrokenAccessControlAttacker } from "./attackers/broken-access-control.js";
import { BrokenObjectAccessAttacker } from "./attackers/broken-object-access.js";
import { MissingAuthenticationAttacker } from "./attackers/missing-authentication.js";
import { UnsafeExecAttacker } from "./attackers/unsafe-exec.js";
import { ResourceExhaustionAttacker } from "./attackers/resource-exhaustion.js";
import { PrototypePollutionAttacker } from "./attackers/prototype-pollution.js";
import { ZipSlipAttacker } from "./attackers/zip-slip.js";
import { SqlInjectionAttacker } from "./attackers/sql-injection.js";
import { StoredTaintAttacker } from "./attackers/stored-taint.js";
import { PolicyBeliefDivergenceAttacker } from "./attackers/policy-belief-divergence.js";
import { SsrfDotnetAttacker } from "./attackers/ssrf-dotnet.js";
import { PathTraversalDotnetAttacker } from "./attackers/path-traversal-dotnet.js";
import { SecondaryInterpreterAttacker } from "./attackers/secondary-interpreter.js";
import { UnsafeDeserializationDotnetAttacker } from "./attackers/unsafe-deserialization-dotnet.js";
import { UnsafeDeserializationAttacker } from "./attackers/unsafe-deserialization.js";
import { ControlPlaneAttacker } from "./attackers/control-plane.js";
import { ExecAuthorizationAttacker } from "./attackers/exec-authorization.js";
import {
  MissingAuthenticationDotnetAttacker,
  DotnetSecurityScanAttacker,
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

/** The registered attack lanes (Node, Swift, Python, Go, and .NET). */
export const ATTACKERS: Attacker[] = [
  new CommandInjectionAttacker(),
  new CommandInjectionDotnetAttacker(),
  new CommandInjectionSwiftAttacker(),
  new CommandInjectionPythonAttacker(),
  new CommandInjectionGoAttacker(),
  new PathTraversalSwiftAttacker(),
  new DifferentialOracleSwiftAttacker(),
  new PathTraversalPythonAttacker(),
  new PathTraversalGoAttacker(),
  new PathTraversalAttacker(),
  new UnsafeExecAttacker(),
  new SsrfSwiftAttacker(),
  new ResourceExhaustionSwiftAttacker(),
  new SqlInjectionSwiftAttacker(),
  new CsvInjectionSwiftAttacker(),
  new SsrfAttacker(),
  new CsvInjectionAttacker(),
  new SqlInjectionAttacker(),
  new SecondaryInterpreterAttacker(),
  new ControlPlaneAttacker(),
  new ExecAuthorizationAttacker(),
  new BrokenAccessControlAttacker(),
  new BrokenObjectAccessAttacker(),
  new MissingAuthenticationAttacker(),
  new ResourceExhaustionAttacker(),
  new PrototypePollutionAttacker(),
  new UnsafeDeserializationAttacker(),
  new ZipSlipAttacker(),
  new StoredTaintAttacker(),
  // Node static lanes: high-risk crypto/token weaknesses surfaced in source (issue #19). Static-only;
  // they contribute leads for the free sweep but are not executed as drive-and-prove lanes.
  // Differential-oracle lane (already an instance, not a class): probes a security-decision control's
  // belief vs ground truth. See src/differential-oracle.ts + PLAYBOOK.md.
  PolicyBeliefDivergenceAttacker,
  // C# (.NET) static lanes — feed the sweep's guard-consistency signal for the Windows node; the
  // execute-gate skips them (staticOnly), so proof is per-lead. Command-injection has its own
  // drive-and-prove .NET lane above (CommandInjectionDotnetAttacker).
  new SsrfDotnetAttacker(),
  new PathTraversalDotnetAttacker(),
  new UnsafeDeserializationDotnetAttacker(),
  MissingAuthenticationDotnetAttacker,
  DotnetSecurityScanAttacker,
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

function sandboxOptionsFor(attacker: Attacker, base: SandboxOptions): SandboxOptions {
  if (!attacker.sandboxImage) return base;
  return { ...base, crabboxImage: attacker.sandboxImage };
}

/**
 * A language match alone is not enough to make a lane applicable: a TypeScript file otherwise
 * wakes every Node attacker and pays every canary cost. Keep the execute phase tied to the same
 * lane-specific static lead used by the free sweep.
 */
function filesWithLeads(targetDir: string, files: string[], attacker: Attacker): string[] {
  return files.filter((file) => {
    if (!attacker.handles(file)) return false;
    try {
      return attacker.staticLeads(readFileSync(join(targetDir, file), "utf8")).length > 0;
    } catch {
      return false;
    }
  });
}

/**
 * Prove a lane is LIVE: open a sandbox over the lane's planted-vulnerable fixture and attack it. A
 * live lane MUST produce at least one exploit against its own planted vuln, else it is quarantined
 * (the family's "caught its own planted defect or it's dead" rule). Returns the sandbox identity
 * used, for the evidence trail.
 */
function proveLaneLive(
  attacker: Attacker,
  box: Sandbox,
): { live: boolean; reason?: string; sandbox: string } {
  try {
    box.seedDir(attacker.canaryFixtureDir);
    const files = handledFilesIn(attacker.canaryFixtureDir, attacker);
    const fired = attacker.hunt(attacker.canaryFixtureDir, files, box);
    return fired.length > 0
      ? { live: true, sandbox: box.name }
      : {
          live: false,
          reason: `${attacker.attackClass} canary did not fire against its planted fixture (${box.name})`,
          sandbox: box.name,
        };
  } catch (err) {
    return { live: false, reason: `canary errored: ${err instanceof Error ? err.message : err}`, sandbox: box.name };
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

  const applicable = ATTACKERS
    .filter((attacker) => !attacker.staticOnly)
    .map((attacker) => ({ attacker, files: filesWithLeads(targetDir, changedFiles, attacker) }))
    .filter(({ files }) => files.length > 0);
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

  for (const { attacker, files: targetFiles } of applicable) {
    const box = openSandbox(targetDir, sandboxOptionsFor(attacker, sbox));
    try {
      const liveness = proveLaneLive(attacker, box);
      sandboxName = liveness.sandbox;
      if (!liveness.live) {
        lanes.push({ attackClass: attacker.attackClass, live: false, attacked: 0, fired: 0, deadReason: liveness.reason });
        continue;
      }
      box.seedDir(targetDir);
      const laneExploits = attacker.hunt(targetDir, targetFiles, box);
      exploits.push(...laneExploits);
      lanes.push({
        attackClass: attacker.attackClass,
        live: true,
        attacked: targetFiles.length,
        fired: laneExploits.length,
      });
    } finally {
      box.dispose();
    }
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
