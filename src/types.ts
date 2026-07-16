// raeuberkrebs (Räuberkrebs) — normalized code-security red-team result shape.
//
// Like signalkrebs (concurrency) there is no killed/total score: an attacker lane either DRIVES a
// payload that actually fires or it does not, and "no payload fired in N attempts" is NOT proof of
// safety. So the verdict is fail-closed and evidence-bearing — a green means the lane was proven
// LIVE (it fired its own planted exploit this run), the touched entrypoints were actually
// REACHED with adversarial input, and nothing fired within the attack budget. Every degenerate
// state (lane couldn't prove itself, surface unreachable, sandbox failure) is an explicit
// non-passing verdict, never a silent pass.
//
// The cardinal rule mirrors the family: a finding is a payload that EXECUTED and produced observed
// proof of compromise (an injected marker ran, a secret file was read out, the process crashed).
// A static "this looks injectable" is a lead for the attacker, never a finding on its own.

/** The attack lanes. Chunk 0 ships `command-injection`; the rest are the Chunk 1 backfill. */
export type AttackClass =
  | "command-injection" // untrusted input reaches a shell/exec sink
  | "sql-injection" // untrusted input concatenated into a query
  | "path-traversal" // untrusted input reaches a filesystem path (../ escape)
  | "unsafe-deserialization" // untrusted bytes into pickle/yaml.load/native deserialize
  | "ssrf" // untrusted input controls an outbound request target
  | "unsafe-exec"; // untrusted input into eval / new Function / dynamic import

export const ATTACK_CLASSES: AttackClass[] = [
  "command-injection",
  "sql-injection",
  "path-traversal",
  "unsafe-deserialization",
  "ssrf",
  "unsafe-exec",
];

/** Terminal verdicts, most-benign first. Only `clean` exits 0. */
export type Verdict =
  | "clean" // touched entrypoints reached with adversarial input, every live lane fired its canary, nothing fired on the target → PASS (exit 0)
  | "vulnerable" // at least one payload fired against the changed surface → FAIL (exit 2)
  | "insufficient" // the changed surface could not be reached/driven with input this run → FAIL-CLOSED (exit 3)
  | "lane-dead" // an applicable attacker could not be proven live (its planted-exploit canary did not fire) → FAIL-CLOSED (exit 3)
  | "error"; // sandbox provision / spawn / timeout / parse failure → ERROR (exit 1)

export const VERDICT_EXIT: Record<Verdict, number> = {
  clean: 0,
  error: 1,
  vulnerable: 2,
  insufficient: 3,
  "lane-dead": 3,
};

/** Where a fired exploit's proof came from — always dynamic here; static is only a lead. */
export type ExploitProof = "marker-executed" | "secret-exfiltrated" | "crash" | "oob-request";

/**
 * A PROVEN exploit: an adversarial payload that was executed against the changed surface in the
 * sandbox and produced observed compromise. This is the unit that fails the gate. An exploit with
 * no `evidence` is a contradiction and is dropped upstream (fail-closed on corrupt findings).
 */
export interface Exploit {
  attackClass: AttackClass;
  proof: ExploitProof;
  /** The changed entrypoint the payload was driven through. */
  file: string;
  line: number;
  /** The sink the payload reached (e.g. `child_process.exec`, `path.join`). */
  sink: string;
  /** One-sentence statement of the exploit. */
  summary: string;
  /** The exact adversarial input that fired — the reproduction. */
  payload: string;
  /**
   * The EVIDENCE the sandbox observed proving the payload fired: the unique injected marker echoed
   * back, the exfiltrated secret-file contents, the crash signal + trace. A finding with no
   * evidence is not a finding.
   */
  evidence: string;
}

/** The result of executing one candidate PoC inside the sandbox. */
export interface SandboxResult {
  fired: boolean;
  proof?: ExploitProof;
  /** Observed evidence when `fired`; the failure/no-fire detail otherwise. */
  evidence: string;
  exitCode: number | null;
  timedOut: boolean;
}

/** Per-lane liveness + outcome for one applicable attacker. */
export interface LaneStatus {
  attackClass: AttackClass;
  /** Proven live this run — the lane fired its own planted-exploit canary before attacking the target. */
  live: boolean;
  /** Entrypoints on the changed surface this lane attacked. */
  attacked: number;
  /** Confirmed exploits this lane produced. */
  fired: number;
  /** Why the lane is not live, when `live` is false (canary failure / missing toolchain). */
  deadReason?: string;
}

/** The overall gate result. */
export interface RaeuberResult {
  verdict: Verdict;
  /** Every proven exploit on the changed surface. Empty on a `clean` pass. */
  exploits: Exploit[];
  lanes: LaneStatus[];
  /** The sandbox provider used to execute PoCs (e.g. "crabbox:docker"), for the evidence trail. */
  sandbox: string;
  /** Human-readable note for a non-`vulnerable` non-`clean` verdict. */
  error: string | null;
  elapsedMs: number;
}
