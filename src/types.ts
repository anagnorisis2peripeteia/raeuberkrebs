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
  | "unsafe-exec" // untrusted input into eval / new Function / dynamic import
  | "csv-injection" // untrusted input reaches a CSV/spreadsheet cell without formula-prefix neutralization
  | "broken-access-control" // a privileged effect is reachable through a path guarded WEAKER than a sibling reaching the same effect (CWE-863/862/269 — differential authorization)
  | "broken-object-access" // a resource is reachable by a caller-controlled key with no ownership check — one principal reads/mutates another's object (CWE-639/CWE-284 — IDOR/BOLA)
  | "missing-authentication" // an inbound/webhook handler performs a privileged action without authenticating the sender or verifying the request signature (CWE-306/CWE-290 — missing auth / spoofing)
  | "resource-exhaustion" // untrusted input reaches a catastrophic-backtracking regex or an unbounded op — a crafted input hangs/OOMs the process (CWE-400/CWE-1333 — ReDoS / uncontrolled resource consumption)
  | "prototype-pollution" // untrusted keys reach a recursive merge/set that writes through `__proto__`/`constructor.prototype`, polluting Object.prototype for every object (CWE-1321)
  | "zip-slip" // an archive entry with a `../` path is written outside the extraction directory — extraction with no path-containment check (CWE-22 archive variant)
  | "weak-crypto" // a broken/weak cryptographic primitive is used (MD5/SHA1 for security, DES/TripleDES/RC2, ECB mode, no padding) — collisions/decryption feasible (CWE-327/328/326)
  | "insecure-tls" // TLS certificate validation is disabled — a custom accept-any-cert callback or revocation turned off makes the node trust any server, enabling MITM (CWE-295)
  | "xxe" // XML parsed with DTD/external-entity resolution enabled on attacker-supplied XML — file read / SSRF via external entities (CWE-611)
  | "insecure-temp-file" // a predictable temp path (Path.GetTempFileName / GetTempPath) holds sensitive data — race / symlink / predictable-name attack (CWE-377)
  | "webview-injection" // untrusted input is concatenated/interpolated into a WebView ExecuteScriptAsync/NavigateToString call — script/HTML injection into the trusted WebView origin (CWE-79/94)
  | "weak-random" // a non-cryptographic RNG (System.Random) generates a security value (token/key/nonce/salt/otp) — predictable / brute-forceable (CWE-330/338)
  | "argument-injection" // untrusted input concatenated into a process ARGUMENT string (ProcessStartInfo.Arguments) rather than an arg list — injects extra flags to the spawned program (CWE-88)
  | "toctou"; // a File/Directory.Exists check guards a later file op on the same path — the path can change between check and use (symlink race) (CWE-367)

export const ATTACK_CLASSES: AttackClass[] = [
  "command-injection",
  "sql-injection",
  "path-traversal",
  "unsafe-deserialization",
  "ssrf",
  "unsafe-exec",
  "csv-injection",
  "broken-access-control",
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
export type ExploitProof =
  | "marker-executed"
  | "secret-exfiltrated"
  | "crash"
  | "oob-request"
  // A benign formula-marker (`=RAEUBER_…`) reached the produced CSV/output as a cell that STILL begins
  // with a formula trigger (= + - @) — un-neutralized, so it would execute in a spreadsheet. The
  // payload never runs in OUR sandbox (it fires in the victim's Excel/Sheets), so the proof is that it
  // SURVIVED into the output unescaped, not that it executed.
  | "formula-unescaped"
  // A privileged EFFECT executed through an entrypoint holding a credential that a SIBLING entrypoint
  // reaching the same effect REJECTS. Like `formula-unescaped`, the proof is differential/observed,
  // not a single injected marker: both entrypoints are executed under the identical low-privilege
  // context, and the fire is that the weak path ran the effect while the strong path denied the same
  // caller with an authorization error — an authority a real caller could exploit to escalate.
  | "privilege-escalated"
  // Principal B read (or mutated) a resource created/owned by principal A, through an entrypoint that
  // resolves the resource from a CALLER-CONTROLLED key without an ownership check. Proven differentially:
  // create a resource as identity A carrying a marker, then reach it as a different identity B — fired
  // means B got A's marker back (IDOR / broken object-level authorization).
  | "foreign-object-accessed"
  // A FORGED inbound request — no valid signature / unauthenticated sender — carrying a benign marker
  // action was ACCEPTED and processed by an ingress handler that reaches a privileged action. Fired
  // means the handler acted on the marker without ever authenticating the request (CWE-306/CWE-290).
  | "unauthenticated-action"
  // A crafted (benign, short) input drove the entrypoint into catastrophic backtracking / an unbounded
  // loop so the call HUNG past the time budget, while a normal input returned fast. The proof is the
  // observed hang differential — availability compromise a single small request can trigger (ReDoS).
  | "input-caused-hang"
  // A payload carrying a `__proto__`/`constructor.prototype` key was merged/assigned into a target, and
  // afterwards a FRESH, unrelated `{}` carried the injected property — proof that `Object.prototype`
  // itself was polluted (every object in the process is now affected). Global-state compromise.
  | "prototype-polluted"
  // An archive entry whose path contains `../` was extracted, and a file with the planted marker
  // appeared OUTSIDE the extraction directory — proof the extractor writes entry paths without a
  // containment check, so an archive can drop files anywhere the process can write (CWE-22 / Zip Slip).
  | "extraction-escaped";

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
