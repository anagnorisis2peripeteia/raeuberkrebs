import { randomBytes } from "node:crypto";
import type { AttackClass, Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";

/**
 * An attacker lane. Each lane knows one vulnerability class, ships a planted-vulnerable fixture its
 * canary must successfully exploit (proving the lane is LIVE — the family's "the detector caught its
 * own planted defect or it's quarantined" rule), and can `hunt` a target for that class.
 *
 * `hunt` runs INSIDE an already-open sandbox over `targetDir`: it detects candidate sinks statically
 * (a free lead), then DRIVES adversarial payloads through the reachable entrypoints and keeps only
 * the ones that fire — a returned Exploit always carries observed evidence.
 */
export interface Attacker {
  readonly attackClass: AttackClass;
  /** True if this lane can attack the given changed file (by language/extension). */
  handles(file: string): boolean;
  /** Absolute path to the planted-vulnerable fixture dir the canary attacks to prove liveness. */
  readonly canaryFixtureDir: string;
  /** Find and PROVE exploits of this class among `files`, using `sandbox` to execute PoCs. */
  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[];
}

/**
 * A per-run, unguessable marker. A payload injects `echo <marker>`; observing `<marker>` back in
 * the sandbox output is proof the injection path executed — it cannot occur by coincidence, and a
 * fixed string could be spoofed by unrelated code, so it must be random per run.
 */
export function freshMarker(): string {
  return "RAEUBER_" + randomBytes(9).toString("hex");
}
