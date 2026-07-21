import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, freshMarker } from "./attacker.js";
import { SWIFT_SOURCE_RE } from "./swift.js";

// Swift differential-oracle lane — the compiled-language sibling of the Node differential oracle.
// Instead of driving a payload through a SINK, it probes a target's own security-DECISION function
// (a confinement resolver, an allow/deny check, an approval gate) and diffs its BELIEF (does it
// approve the input?) against GROUND TRUTH (does acting on the approved input actually escape /
// execute?). belief=approved AND ground-truth=escaped  ->  a proven bypass of the control's own gate.
//
// It is generic and extensible, not per-target: it auto-discovers decision functions by shape and
// picks a ground-truth STRATEGY from a registry. `MCPFilesystemGuard.resolve` compiles in isolation
// (Foundation-only), so the guard is drivable; a decision function that needs the rest of its package
// won't build in isolation (an honest miss). Runs on the macOS host.

const HERE = dirname(fileURLToPath(import.meta.url));

/** A decision (belief) function: a String-first-arg function whose name reads like a security gate. */
interface DecisionFunction {
  name: string;
  firstLabel: string; // external label of the first (String) parameter; "_" = no label
  enclosingType: string | null;
  isStatic: boolean;
  throws: boolean;
  returnType: string | null; // trimmed return type, or null for Void
  body: string; // the function body — inspected for a genuine confinement/boundary check
}

// Names that read like a security decision over an untrusted input.
const DECISION_NAME_RE =
  /^(?:is|assert|validate|verify|check|ensure|require|authorize|authorise|allow|permit|resolve|confine|canonical|sanitize|sanitise|guard|safe|approve|contains)/i;

/** Parse decision functions whose FIRST parameter is a `String`. Captures throws + return type. */
export function swiftDecisionFunctions(source: string): DecisionFunction[] {
  const out: DecisionFunction[] = [];
  // func [static] name(label? _name: String[?] , ...) [async] [throws] [-> Ret] {
  const re =
    /\bfunc\s+([A-Za-z_]\w*)\s*\(\s*(?:([A-Za-z_]\w*)\s+)?([A-Za-z_]\w*)\s*:\s*String\b[^)]*\)\s*((?:async\s+)?(?:throws\s+)?)(?:->\s*([^\{]+?)\s*)?\{/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source)) !== null) {
    const before = source.slice(0, m.index);
    const mods = before.slice(before.lastIndexOf("\n") + 1);
    if (/\b(?:private|fileprivate)\b/.test(mods)) continue; // not visible to the driver
    const name = m[1];
    if (!DECISION_NAME_RE.test(name)) continue;
    const firstLabel = m[2] === undefined ? "_" : m[2]; // `_name: String` has no external label token here
    const enclosingType = enclosingTypeAt(source, m.index);
    const braceIndex = m.index + m[0].length - 1; // the `{` at the end of the signature match
    out.push({
      name,
      firstLabel,
      enclosingType,
      isStatic: /\bstatic\b/.test(mods),
      throws: /\bthrows\b/.test(m[4] ?? ""),
      returnType: (m[5] ?? "").trim() || null,
      body: sliceBracedBody(source, braceIndex),
    });
  }
  return out;
}

/** The `{ ... }` body starting at `braceIndex` (a `{`), via brace matching. */
function sliceBracedBody(source: string, braceIndex: number): string {
  let depth = 0;
  for (let i = braceIndex; i < source.length; i++) {
    const ch = source[i];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return source.slice(braceIndex, i + 1);
    }
  }
  return source.slice(braceIndex);
}

// A genuine confinement/boundary DECISION — the function BELIEVES it keeps a path inside a base.
// Mere path normalization (`standardizedFileURL`, `expandingTildeInPath`) is NOT a boundary belief:
// a normalizer that returns any absolute path has no containment contract to diverge from. Require an
// actual boundary test (prefix/`..`/allowed-root check, or an explicit confinement name).
const CONFINEMENT_BODY_RE =
  /\.hasPrefix\(\s*[A-Za-z_]|contains\(\s*["']\.\.|allowedRoots?\b|withinBase|isWithin|\bconfine|guardPath|outsideAllowed|fsRoots?\b|baseDir\b|rootDir\b|allowed[_ ]?dir/i;
const CONFINEMENT_NAME_RE = /confine|withinbase|validatepath|guardpath|sandbox|allowedroot|isallowedpath/i;
const FS_TOUCH_RE = /appendingPathComponent|fileURLWithPath|contentsOfFile|FileManager|URL\(\s*fileURL/;

function enclosingTypeAt(source: string, index: number): string | null {
  const before = source.slice(0, index);
  const matches = [...before.matchAll(/\b(?:class|struct|enum|extension|actor)\s+([A-Za-z_]\w*)/g)];
  for (let i = matches.length - 1; i >= 0; i--) {
    if (matches[i][1] !== "func") return matches[i][1];
  }
  return null;
}

/** The call receiver: `Type.method` for a static/type method, else the bare method (free function). */
function receiverExpr(fn: DecisionFunction): string {
  return fn.enclosingType && fn.isStatic ? `${fn.enclosingType}.${fn.name}` : fn.name;
}

function callExpr(fn: DecisionFunction, argVar: string): string {
  const arg = fn.firstLabel === "_" ? argVar : `${fn.firstLabel}: ${argVar}`;
  return `${receiverExpr(fn)}(${arg})`;
}

type Strategy = "fs-escape" | "exec-marker";

/**
 * Which ground-truth strategy fits this decision function (extensible seam). fs-escape fires only for
 * a GENUINE confinement decision — a path-shaped function that touches the filesystem AND actually
 * performs a boundary check it believes enforces containment. A bare path normalizer (no boundary
 * test) has no confinement belief to diverge from and is deliberately excluded (no false positives).
 */
function strategyFor(fn: DecisionFunction): Strategy | null {
  const rt = (fn.returnType ?? "").toLowerCase();
  const name = fn.name.toLowerCase();
  const pathReturn = /\burl\b|string/.test(rt);
  const pathName = /path|file|dir|resolve|confine|canonical|sanitize|root/.test(name);
  const boundaryBelief = CONFINEMENT_BODY_RE.test(fn.body) || CONFINEMENT_NAME_RE.test(name);
  const touchesFs = FS_TOUCH_RE.test(fn.body);
  // fs-escape: a path-shaped (returns or names a path) confinement decision that touches the FS AND
  // performs a real boundary check. Excludes Bool app-state checks (isApplicationRunning) that only
  // incidentally match a boundary pattern.
  if ((pathReturn || pathName) && boundaryBelief && touchesFs) return "fs-escape";
  // exec-marker: a command/launch-approval gate. Belief = it approves; ground truth = running the
  // approved input fires the benign marker.
  const execName = /exec|command|shell|\brun\b|launch|spawn|executable|gatekeeper|approve/.test(name);
  const execBody = /Process\(|\bsystem\(|posix_spawn|\.launch|executableURL|launchPath/.test(fn.body);
  if ((execName || execBody) && (/\bbool\b/.test(rt) || fn.throws)) return "exec-marker";
  return null;
}

// Payloads that a correct confinement check must DENY; if a control approves one and the write
// escapes the sandbox base, belief has diverged from ground truth.
const FS_PAYLOADS = [
  "../rk-oracle-out/escape.txt", // parent-escape
  "../../rk-oracle-out/escape.txt",
  "link/escape.txt", // through an in-base symlink to the out-of-base dir
  "base/ok.txt", // legitimate in-base control (must NOT be a divergence)
];

/**
 * The Swift belief block: sets `approved` (did the control approve the payload?) and `target` (the
 * path to materialize for ground truth — the control's returned path when it returns one, else the
 * payload joined under base). Generated per return shape so optional/throwing types compile.
 */
function beliefBlock(fn: DecisionFunction): string {
  const rt = (fn.returnType ?? "").toLowerCase();
  const opt = rt.endsWith("?");
  const thr = fn.throws;
  const call = callExpr(fn, "payload");
  const returnsURL = /\burl\b/.test(rt);
  const returnsString = /string/.test(rt) && !returnsURL;
  const returnsBool = /\bbool\b/.test(rt);

  if (returnsBool) {
    // Bool gate: approved == returned true.
    return thr ? `approved = ((try? ${call}) ?? false)` : `approved = ${call}`;
  }
  if (returnsURL || returnsString) {
    const pathOf = returnsURL ? ".path" : "";
    // Unwrap throws and/or Optional down to a single value, then read its path.
    if (thr && opt) return `if let __r0 = try? ${call}, let __r = __r0 { approved = true; target = __r${pathOf} }`;
    if (thr && !opt) return `if let __r = try? ${call} { approved = true; target = __r${pathOf} }`;
    if (!thr && opt) return `if let __r = ${call} { approved = true; target = __r${pathOf} }`;
    return `let __r = ${call}; approved = true; target = __r${pathOf}`; // non-optional, non-throwing: always approves
  }
  // Throwing with no meaningful return (Void / opaque): approved == did not throw.
  return `approved = ((try? ${call}) != nil)`;
}

/** A `main.swift` that runs belief-vs-ground-truth for the fs-escape strategy over the payloads. */
function fsEscapeDriver(fn: DecisionFunction): string {
  return `import Foundation

let fm = FileManager.default
let cwd = fm.currentDirectoryPath
let base = cwd + "/base"
let outside = cwd + "/rk-oracle-out"
try? fm.createDirectory(atPath: base, withIntermediateDirectories: true)
try? fm.createDirectory(atPath: outside, withIntermediateDirectories: true)
// An in-base symlink pointing at the out-of-base directory (the classic confinement escape).
try? fm.removeItem(atPath: base + "/link")
try? fm.createSymbolicLink(atPath: base + "/link", withDestinationPath: outside)

func realOutside(_ path: String) -> Bool {
  // Materialize a marker at \`path\` and report whether it physically landed outside \`base\`.
  let mark = "RK_MARK_\\(UInt64.random(in: 0..<UInt64.max))"
  let url = URL(fileURLWithPath: path)
  try? fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
  guard (try? mark.data(using: .utf8)?.write(to: url)) != nil else { return false }
  let real = (url.path as NSString).resolvingSymlinksInPath
  let baseReal = (base as NSString).resolvingSymlinksInPath
  return !(real == baseReal || real.hasPrefix(baseReal + "/"))
}

for payload in ${JSON.stringify(FS_PAYLOADS)} {
  var approved = false
  var target = base + "/" + payload
  ${beliefBlock(fn)}
  if !approved { continue }               // control denied it -> not a bypass
  if realOutside(target) {
    print("RK_DIVERGENCE " + payload)      // approved AND the write escaped base
  }
}
`;
}

/** The belief expression for exec-marker: TRUE when the gate approves the payload. */
function execApprovedExpr(fn: DecisionFunction): string {
  const rt = (fn.returnType ?? "").toLowerCase();
  const call = callExpr(fn, "payload");
  if (/\bbool\b/.test(rt)) return fn.throws ? `((try? ${call}) ?? false)` : `(${call})`;
  return `((try? ${call}) != nil)`; // throws / opaque: approved == did not throw
}

/** A `main.swift` for the exec-marker strategy: the gate approved an input that actually ran. */
function execMarkerDriver(fn: DecisionFunction): string {
  return `import Foundation

let MARK = "RK_EXEC_\\(UInt64.random(in: 0..<UInt64.max))"
let cwd = FileManager.default.currentDirectoryPath
// Plant a marker executable so a "launch this path" gate can be probed with a real exec.
let markExec = cwd + "/rk-mark.sh"
try? ("#!/bin/sh\\necho " + MARK + "\\n").write(toFile: markExec, atomically: true, encoding: .utf8)
_ = try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: markExec)

func ran(_ payload: String) -> Bool {
  let p = Process()
  p.executableURL = URL(fileURLWithPath: "/bin/sh")
  p.arguments = ["-c", payload]
  let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
  do { try p.run(); p.waitUntilExit() } catch { return false }
  let d = pipe.fileHandleForReading.readDataToEndOfFile()
  return (String(data: d, encoding: .utf8) ?? "").contains(MARK)
}

let corpus = [markExec, "echo " + MARK, "/bin/sh -c 'echo " + MARK + "'"]
for payload in corpus {
  let approved = ${execApprovedExpr(fn)}
  if !approved { continue }               // gate denied it -> not a bypass
  if ran(payload) { print("RK_DIVERGENCE " + payload) }   // approved AND executed the marker
}
`;
}

export class DifferentialOracleSwiftAttacker implements Attacker {
  readonly attackClass = "path-traversal" as const; // confinement-decision divergence
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "differential-oracle-swift");

  handles(file: string): boolean {
    return SWIFT_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    const leads: StaticLead[] = [];
    const lines = source.split("\n");
    const decisions = swiftDecisionFunctions(source);
    for (const fn of decisions) {
      if (!strategyFor(fn)) continue;
      const idx = lines.findIndex((l) => new RegExp(`func\\s+${fn.name}\\b`).test(l));
      leads.push({
        line: idx >= 0 ? idx + 1 : 1,
        sink: `belief:${receiverExpr(fn)}() — differential-oracle decision candidate`,
      });
    }
    return leads;
  }

  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
    const exploits: Exploit[] = [];
    for (const file of files) {
      if (!this.handles(file)) continue;
      let source: string;
      try {
        source = readFileSync(join(targetDir, file), "utf8");
      } catch {
        continue;
      }
      const decisions = swiftDecisionFunctions(source)
        .map((fn) => ({ fn, strat: strategyFor(fn) }))
        .filter((d): d is { fn: DecisionFunction; strat: Strategy } => d.strat !== null);
      if (decisions.length === 0) continue;

      for (const { fn, strat } of decisions) {
        const marker = freshMarker();
        const dir = `.rk-oracle-${marker}`;
        const bin = `${dir}/drv`;
        const driver = strat === "fs-escape" ? fsEscapeDriver(fn) : execMarkerDriver(fn);
        sandbox.exec(`mkdir -p ${dir}`, 10_000);
        sandbox.writeFile(`${dir}/Target.swift`, source);
        sandbox.writeFile(`${dir}/main.swift`, driver);
        sandbox.exec(
          `cd ${dir} && swiftc -suppress-warnings Target.swift main.swift -o drv 2>&1`,
          180_000,
        );
        const check = sandbox.exec(`test -x ${bin} && echo RK_BIN_OK || echo RK_NO_BIN`, 10_000);
        if (!check.stdout.includes("RK_BIN_OK")) continue; // didn't compile in isolation — honest miss

        const run = sandbox.exec(`cd ${dir} && ./drv 2>&1`, 30_000);
        const out = run.stdout + run.stderr;
        const diverged = [...out.matchAll(/^RK_DIVERGENCE (.+)$/gm)].map((m) => m[1].trim());
        if (diverged.length === 0) continue;
        const receiver = receiverExpr(fn);
        const isFs = strat === "fs-escape";
        exploits.push({
          attackClass: isFs ? "path-traversal" : "command-injection",
          proof: "belief-diverged",
          file,
          line: 1,
          sink: `belief:${receiver}`,
          summary: isFs
            ? `The confinement decision \`${receiver}()\` APPROVED ${diverged.length} path(s) whose write escaped the allowed base — belief (approved) diverges from ground truth (escaped).`
            : `The command/launch gate \`${receiver}()\` APPROVED ${diverged.length} input(s) that executed the benign marker — belief (approved) diverges from ground truth (executed).`,
          payload: diverged[0],
          evidence:
            `${receiver}() approved: ${diverged.join(", ")}\n` +
            (isFs ? "materializing each escaped the sandbox base" : "running each fired the benign marker") +
            `:\n${out.slice(0, 800)}`,
        });
      }
    }
    return exploits;
  }
}
