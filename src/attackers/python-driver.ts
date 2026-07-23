// Shared drive-and-prove plumbing for the Python lanes.
//
// The defining problem this module solves: a Python attacker lane proves a vuln by importing the
// target module and calling an exported function with an adversarial payload. The naive way to load
// a file — `importlib.util.spec_from_file_location(...)` + `exec_module` — loads it as a STANDALONE
// module with no package parent. That works for a self-contained fixture, but on any real package
// the very first `from .server import dispatch` / `from pkg.sub import x` raises ImportError, the
// driver prints IMPORT_FAIL, and the lane silently sees zero fired → a FALSE CLEAN. That is the
// Python twin of the Node build-toolchain false-clean that `bundleForImport` fixed.
//
// The fix is `_load_target` (in PYTHON_LOAD_TARGET_SRC below): compute the module's real dotted name
// by walking up `__init__.py` markers, put the package ROOT on `sys.path`, and
// `importlib.import_module(dotted)` so the module loads WITH its package context and intra-package
// imports resolve. It falls back to the old spec-from-file load on failure, so the mechanism is a
// STRICT SUPERSET of the old one. Every Python driver embeds this same source, so they all inherit
// the fix (and third-party deps are handled orthogonally by `ensurePythonEnv`'s opt-in venv).

/** The runtime image Python lanes need when driving inside crabbox. */
export const PYTHON_SANDBOX_IMAGE = "python:3-bookworm-slim";

interface PythonFn {
  name: string;
}

/**
 * Top-level `def name(arg, …)` entrypoints we can drive in isolation: a module-level function whose
 * first parameter is positional (so the payload can flow in as the untrusted first argument).
 */
export function topLevelFunctions(source: string): PythonFn[] {
  // Match `def name(` with at least one parameter, tolerating type annotations, defaults, `*args`, and
  // multiline signatures (`\s*` spans newlines). The old pattern required an UN-annotated first param
  // followed immediately by `,`/`)`, so it silently skipped every typed function — i.e. essentially all
  // modern Python (`def f(cmd: str) -> bool:`) — making the lanes false-clean on real typed code.
  const re = /^def\s+([A-Za-z_]\w*)\s*\(\s*[A-Za-z_*]/gm;
  const names: string[] = [];
  for (const m of source.matchAll(re)) names.push(m[1]);
  return [...new Set(names)].map((name) => ({ name }));
}

/** Single-quote a string for a POSIX shell command line. */
export function shq(s: string): string {
  return "'" + s.replace(/'/g, `'\\''`) + "'";
}

/**
 * The shared import-as-package loader: `import`s plus `_load_target(rel)`. Embedded verbatim by every
 * Python driver so they all get the package-context import fix and its strict-superset fallback.
 */
export const PYTHON_LOAD_TARGET_SRC = `
import os
import sys
import importlib
import importlib.util


def _load_target(rel):
  # Resolve the module's dotted name by walking up the tree while __init__.py marks a package, then
  # import it with that name so its intra-package imports resolve. Falls back to a standalone
  # spec-from-file load when the file is not inside a package (self-contained scripts / fixtures),
  # OR when the package import fails (e.g. a parent __init__.py pulls a heavy dep) but the leaf module
  # is self-contained — that fallback keeps the new mechanism a STRICT SUPERSET of the old one.
  path = os.path.abspath(rel)
  base = os.path.splitext(os.path.basename(path))[0]
  parts = [] if base == "__init__" else [base]
  d = os.path.dirname(path)
  while os.path.isfile(os.path.join(d, "__init__.py")):
    parts.insert(0, os.path.basename(d))
    d = os.path.dirname(d)
  if parts:
    if d not in sys.path:
      sys.path.insert(0, d)
    try:
      return importlib.import_module(".".join(parts))
    except Exception:
      pass
  pkg_dir = os.path.dirname(path)
  if pkg_dir not in sys.path:
    sys.path.insert(0, pkg_dir)
  spec = importlib.util.spec_from_file_location("raeuber_target", path)
  if spec is None or spec.loader is None:
    raise ImportError("no import spec for " + rel)
  m = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(m)
  return m
`.trim();

/**
 * Driver for the injection lanes (command-injection, path-traversal): decode the base64 payload from
 * RAEUBER_PAYLOAD_B64, import the target WITH package context, resolve `fnName`, call `fn(payload)`.
 * Prints IMPORT_FAIL / NOT_A_FUNCTION on the honest failure paths. CalledProcessError output is
 * surfaced too, since a shell sink that raises still carries the fired marker in its captured stdout.
 */
export function pythonDriver(moduleFile: string, fnName: string): string {
  const target = JSON.stringify(moduleFile);
  const fn = JSON.stringify(fnName);
  return `
import base64
${PYTHON_LOAD_TARGET_SRC}

payload_b64 = os.environ.get("RAEUBER_PAYLOAD_B64", "")
try:
  payload = base64.b64decode(payload_b64).decode("utf-8", "replace")
except Exception as e:
  print("BASE64_FAIL:" + str(e))
  raise SystemExit(0)

try:
  mod = _load_target(${target})
except Exception as e:
  print("IMPORT_FAIL:" + repr(e))
  raise SystemExit(0)

fn = getattr(mod, ${fn}, None)
if not callable(fn):
  print("NOT_A_FUNCTION")
  raise SystemExit(0)

try:
  r = fn(payload)
  if r is not None:
    print(r)
except Exception as e:
  out = getattr(e, "stdout", None)
  if isinstance(out, (bytes, bytearray)):
    out = out.decode("utf-8", "replace")
  print(out or str(e))
`.trim();
}

/** Deserialization families we can drive-and-prove: pickle-protocol loaders and unsafe YAML loaders. */
export type DeserMode = "pickle" | "yaml";

/**
 * Driver for the unsafe-deserialization lane. The proof is a benign, ECHO-PROOF, SHELL-FREE side
 * effect: a gadget tells the deserializer to call `open(SENTINEL, "w")`, which creates a sentinel
 * FILE. Only real deserialization (executing the gadget) creates it — a function that merely echoes
 * the payload back cannot — so there is no false positive from payload reflection. The driver checks
 * for the file after each call.
 *
 * - pickle family: `pickle.dumps(gadget)` where `gadget.__reduce__` → `(open, (SENTINEL, "w"))`.
 * - unsafe YAML: `!!python/object/apply:builtins.open ["SENTINEL", "w"]` (fires only under an unsafe
 *   loader — a modern `yaml.load`/FullLoader blocks `apply`, so a safe caller correctly does NOT fire).
 */
export function unsafeDeserPythonDriver(
  moduleFile: string,
  fnName: string,
  marker: string,
  modes: DeserMode[],
): string {
  const target = JSON.stringify(moduleFile);
  const fn = JSON.stringify(fnName);
  const mk = JSON.stringify(marker);
  const modeList = JSON.stringify(modes);
  return `
import pickle
${PYTHON_LOAD_TARGET_SRC}

MARKER = ${mk}
SENTINEL = os.path.abspath(".rk-deser-fired-" + MARKER)
MODES = ${modeList}

try:
  mod = _load_target(${target})
except Exception as e:
  print("IMPORT_FAIL:" + repr(e))
  raise SystemExit(0)

fn = getattr(mod, ${fn}, None)
if not callable(fn):
  print("NOT_A_FUNCTION")
  raise SystemExit(0)


class _PickleGadget:
  # On unpickling, pickle calls open(SENTINEL, "w") — a benign file side effect that only real
  # deserialization can trigger. No shell, no network, nothing destructive.
  def __reduce__(self):
    return (open, (SENTINEL, "w"))


def _clear():
  try:
    if os.path.exists(SENTINEL):
      os.remove(SENTINEL)
  except Exception:
    pass


def _call(payload):
  try:
    fn(payload)
  except Exception:
    pass  # a raised exception does not invalidate the PoC — the file side effect is the proof


for mode in MODES:
  _clear()
  if mode == "pickle":
    _call(pickle.dumps(_PickleGadget()))
  elif mode == "yaml":
    _call('!!python/object/apply:builtins.open ["' + SENTINEL + '", "w"]')
  if os.path.exists(SENTINEL):
    # Marker printed ONLY after the file side effect is confirmed, so it stays echo-proof while tying
    # the evidence to this run's fresh nonce.
    print("UNSAFE_DESER_FIRED mode=" + mode + " marker=" + MARKER)
    _clear()
    raise SystemExit(0)

print("UNSAFE_DESER_NOFIRE")
`.trim();
}

/**
 * Driver for the command-approval differential oracle (the "the control believes this is safe, but it
 * actually executes" class). For each discovered decision function and each adversarial command in the
 * corpus: BELIEF = the control returns truthy for the command; GROUND TRUTH = running the command in a
 * shell fires the benign marker. A divergence (believed-safe AND fired) is a proven bypass — the gate
 * auto-approves a command carrying shell injection. A sound gate that rejects shell metacharacters
 * correctly does NOT fire. `corpus` items are already marker-substituted by the lane.
 */
export function differentialOraclePythonDriver(
  moduleFile: string,
  fnNames: string[],
  marker: string,
  corpus: string[],
): string {
  const target = JSON.stringify(moduleFile);
  const fns = JSON.stringify(fnNames);
  const mk = JSON.stringify(marker);
  const corpusJson = JSON.stringify(corpus);
  return `
import json
import subprocess
${PYTHON_LOAD_TARGET_SRC}

MARKER = ${mk}
CORPUS = ${corpusJson}
FNS = ${fns}

try:
  mod = _load_target(${target})
except Exception as e:
  print("IMPORT_FAIL:" + repr(e))
  raise SystemExit(0)


def _ground_truth_fired(cmd):
  # Run the command in a shell; fired = the benign marker actually executed. Time-boxed and benign.
  try:
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=4)
    return MARKER in (r.stdout + r.stderr)
  except Exception as e:
    out = getattr(e, "stdout", "") or ""
    if isinstance(out, (bytes, bytearray)):
      out = out.decode("utf-8", "replace")
    return MARKER in out


for fname in FNS:
  fn = getattr(mod, fname, None)
  if not callable(fn):
    continue
  for cmd in CORPUS:
    try:
      believed = fn(cmd) is True
    except Exception:
      continue  # the control errored on this input — not a clean approval
    if not believed:
      continue  # control says unsafe / returned a non-True report -> not a clean approval
    if _ground_truth_fired(cmd):
      print("RK_DIVERGENCE fn=" + fname + " " + json.dumps(cmd))
`.trim();
}

/**
 * A (control, carrier) pair for a coverage-differential oracle. `control` is a command of a danger
 * CATEGORY that a working guard already flags; `carrier` is an equivalent-intent command of the SAME
 * category (a different tool/spelling reaching the same effect) that may slip an incomplete denylist.
 * The finding is the VERDICT DIVERGENCE — the guard flags `control` but clears `carrier` — which
 * proves a category coverage gap rather than a disabled guard (a fire requires `control` to still
 * flag). Both strings are only ever passed to the target's pure classifier; neither is executed.
 */
export interface CoverageDiffItem {
  control: string;
  carrier: string;
  category: string;
  technique: string;
}

/**
 * Driver for the coverage-differential oracle (incomplete-denylist detection). For each discovered
 * danger-DETECTOR and each (control, carrier) pair: fire when the detector FLAGS the control but
 * CLEARS the carrier of the same danger category. The `control`-flags requirement means an inert
 * function (flags nothing) never fires — a divergence, not a disabled guard, is the signal.
 *
 * Safety: the detector is only ever called as a pure string classifier; NO carrier is ever executed
 * (unlike the ground-truth oracle, this lane never runs a command). The carriers are curated,
 * genuinely-dangerous siblings, so a flag-control-clear-carrier divergence is a real bypass.
 */
export function coverageDifferentialDriver(
  moduleFile: string,
  detectorNames: string[],
  corpus: CoverageDiffItem[],
): string {
  const target = JSON.stringify(moduleFile);
  const detectors = JSON.stringify(detectorNames);
  const corpusJson = JSON.stringify(corpus);
  return `
import json
${PYTHON_LOAD_TARGET_SRC}

DETECTORS = ${detectors}
CORPUS = ${corpusJson}

try:
  mod = _load_target(${target})
except Exception as e:
  print("IMPORT_FAIL:" + repr(e))
  raise SystemExit(0)


def _flagged(r):
  # A detector's verdict: bool, or a tuple/list whose first element is the boolean (the common
  # \`(is_dangerous, reason)\` / \`(matched, key, desc)\` shapes), or a truthy report object.
  if isinstance(r, (tuple, list)):
    return bool(r[0]) if r else False
  return bool(r)


for dname in DETECTORS:
  d = getattr(mod, dname, None)
  if not callable(d):
    continue
  for item in CORPUS:
    try:
      flagged_control = _flagged(d(item["control"]))
      flagged_carrier = _flagged(d(item["carrier"]))
    except Exception:
      continue  # the control errored on an input -> not a clean divergence
    if flagged_control and not flagged_carrier:
      # guard flags a gated sibling of this danger category but clears the equivalent carrier -> gap
      print("RK_COVERAGE fn=" + dname + " " + json.dumps(item))
`.trim();
}

/**
 * A same-line-assignment command-name indirection item. `control` is the resolved dangerous command
 * the guard flags; `carrier` is its indirection form (`CMD=rm; $CMD -rf /`) the guard clears because it
 * never resolves the assignment; `markerForm` is a BENIGN twin using the identical assignment mechanism
 * but a marker-echo command (`V=echo; $V <MARK>`), run in bash to prove the mechanism resolves at
 * runtime. Only `markerForm` is ever executed — the dangerous `carrier`/`control` are only classified.
 */
export interface AssignmentIndirectionItem {
  control: string;
  carrier: string;
  /** benign marker-echo twin with `{{MARK}}` where the fresh marker is substituted. */
  markerForm: string;
  technique: string;
}

/**
 * Driver for the assignment-indirection oracle (issue #93). For each discovered danger-detector and
 * each item: fire when the detector FLAGS the resolved `control` but CLEARS the same-line-assignment
 * `carrier`, AND bash proves the assignment mechanism resolves at runtime (the benign `markerForm`
 * echoes the marker). The runtime proof distinguishes a real assignment-resolution bypass from a naive
 * `$VAR` over-block: only a same-line assignment that actually collapses fires.
 *
 * Safety: the dangerous `control`/`carrier` are only passed to the pure classifier; the sole shell call
 * runs the BENIGN `markerForm` (`V=echo; $V <marker>`), which echoes the marker and nothing else.
 */
export function assignmentIndirectionDriver(
  moduleFile: string,
  detectorNames: string[],
  marker: string,
  corpus: AssignmentIndirectionItem[],
): string {
  const target = JSON.stringify(moduleFile);
  const detectors = JSON.stringify(detectorNames);
  const mk = JSON.stringify(marker);
  const corpusJson = JSON.stringify(corpus);
  return `
import json
import subprocess
${PYTHON_LOAD_TARGET_SRC}

MARKER = ${mk}
DETECTORS = ${detectors}
CORPUS = ${corpusJson}

try:
  mod = _load_target(${target})
except Exception as e:
  print("IMPORT_FAIL:" + repr(e))
  raise SystemExit(0)


def _flagged(r):
  if isinstance(r, (tuple, list)):
    return bool(r[0]) if r else False
  return bool(r)


def _collapses(marker_form):
  # Benign: run the marker-echo twin (V=echo; $V <marker>). The marker prints ONLY if the same-line
  # assignment + expansion resolves at runtime — the mechanism the guard failed to model.
  try:
    r = subprocess.run(["bash", "-c", marker_form], capture_output=True, text=True, timeout=4)
    return MARKER in (r.stdout + r.stderr)
  except Exception:
    return False


for dname in DETECTORS:
  d = getattr(mod, dname, None)
  if not callable(d):
    continue
  for item in CORPUS:
    try:
      flagged_control = _flagged(d(item["control"]))
      flagged_carrier = _flagged(d(item["carrier"]))
    except Exception:
      continue
    if not (flagged_control and not flagged_carrier):
      continue  # no verdict flip -> the guard is not evaded by this indirection
    marker_form = item["markerForm"].replace("{{MARK}}", MARKER)
    if _collapses(marker_form):
      # guard flags the resolved command, clears its assignment-indirection form, and bash proves the
      # assignment mechanism resolves at runtime -> a real hardline-floor bypass
      print("RK_ASSIGN fn=" + dname + " " + json.dumps({"control": item["control"], "carrier": item["carrier"], "technique": item["technique"]}))
`.trim();
}

/** A known secret format to drive a scrubber with. `secret` is a format-VALID instance carrying an
 *  unguessable `sentinel` substring; a surviving `sentinel` in the scrubber's output proves that format
 *  leaked. The sentinel is chosen format-valid (e.g. uppercase-hex for an `AKIA[0-9A-Z]{16}` body) so
 *  embedding it does not itself break the pattern the scrubber matches — a false leak. */
export interface SecretBatteryItem {
  label: string;
  secret: string;
  sentinel: string;
}

/**
 * Driver for the redaction-completeness oracle (issue #89). For each discovered scrub/redact function
 * and each secret in the battery: call the function and fire when that secret's SENTINEL SURVIVES in
 * the output (that format was not redacted). Because the sentinel is a format-valid substring of the
 * secret token, a scrubber that redacts the token removes the sentinel; only a MISSED format leaks it.
 * A function that returns its input unchanged (redacts nothing) leaks EVERY secret — a true finding.
 */
export function redactionCompletenessDriver(
  moduleFile: string,
  fnNames: string[],
  battery: SecretBatteryItem[],
): string {
  const target = JSON.stringify(moduleFile);
  const fns = JSON.stringify(fnNames);
  const batteryJson = JSON.stringify(battery);
  return `
import json
${PYTHON_LOAD_TARGET_SRC}

FNS = ${fns}
BATTERY = ${batteryJson}

try:
  mod = _load_target(${target})
except Exception as e:
  print("IMPORT_FAIL:" + repr(e))
  raise SystemExit(0)


def _scrub(fn, secret):
  # Call the scrubber. Tolerate (text) or (text, extra) signatures; a raise means it did not scrub this
  # input, which is itself a leak of the original (caller would fall back to the raw text).
  try:
    r = fn(secret)
  except TypeError:
    try:
      r = fn(secret, False)
    except Exception:
      return secret
  except Exception:
    return secret
  return r if isinstance(r, str) else (r[0] if isinstance(r, (tuple, list)) and r else str(r))


for fname in FNS:
  fn = getattr(mod, fname, None)
  if not callable(fn):
    continue
  for item in BATTERY:
    out = _scrub(fn, item["secret"])
    if item["sentinel"] in out:
      # the secret's format-valid sentinel survived the scrubber -> this format leaks in cleartext
      print("RK_REDACT_LEAK fn=" + fname + " " + json.dumps({"label": item["label"]}))
`.trim();
}

/**
 * Driver for the redaction MODE-differential oracle (issue #91). Drives the SAME marker-carrying input
 * across the scrubber's context modes (e.g. default vs `file_read=True`/`code_file=True`) and fires
 * when the marker is REDACTED in one mode but SURVIVES in another — a self-contained inconsistency that
 * needs no ground-truth "is this secret" list, only that two modes disagree for the same bytes.
 *
 * `modes` is a list of {name, kwargs} the driver calls as `fn(secret, **kwargs)`. `inputs` are
 * marker-carrying config-secret forms; the source-code negatives (os.getenv, numeric consts) must be
 * consistent across modes (redacted in all or passed in all) to avoid false positives.
 */
export function redactionModeDifferentialDriver(
  moduleFile: string,
  fnNames: string[],
  inputs: SecretBatteryItem[],
  modes: Array<{ name: string; kwargs: Record<string, unknown> }>,
): string {
  const target = JSON.stringify(moduleFile);
  const fns = JSON.stringify(fnNames);
  const inputsJson = JSON.stringify(inputs);
  // MODES contains JSON booleans in kwargs (true/false), which are not valid Python literals — decode
  // it with json.loads from a double-encoded string so the kwargs become real Python bools.
  const modesLiteral = JSON.stringify(JSON.stringify(modes));
  return `
import json
${PYTHON_LOAD_TARGET_SRC}

FNS = ${fns}
INPUTS = ${inputsJson}
MODES = json.loads(${modesLiteral})

try:
  mod = _load_target(${target})
except Exception as e:
  print("IMPORT_FAIL:" + repr(e))
  raise SystemExit(0)


def _scrub(fn, secret, kwargs):
  try:
    r = fn(secret, **kwargs)
  except TypeError:
    return None  # this mode's signature does not apply to this function
  except Exception:
    return secret
  return r if isinstance(r, str) else (r[0] if isinstance(r, (tuple, list)) and r else str(r))


for fname in FNS:
  fn = getattr(mod, fname, None)
  if not callable(fn):
    continue
  for item in INPUTS:
    verdicts = {}
    for mode in MODES:
      out = _scrub(fn, item["secret"], mode["kwargs"])
      if out is None:
        continue
      verdicts[mode["name"]] = item["sentinel"] in out  # True = leaked in this mode
    leaked = [m for m, v in verdicts.items() if v]
    redacted = [m for m, v in verdicts.items() if not v]
    if leaked and redacted:
      # the same secret is redacted in one mode but leaks in another -> a mode-differential bug
      print("RK_REDACT_MODEDIFF fn=" + fname + " " + json.dumps({"label": item["label"], "leaked_in": leaked, "redacted_in": redacted}))
`.trim();
}

/** A (dangerous seed, shell-obfuscated variant) pair whose forms bash expands identically. */
export interface NormDiffItem {
  plain: string;
  obf: string;
  technique: string;
}

/**
 * Driver for the normalization-differential oracle (fail-open guard detection). For each discovered
 * danger-DETECTOR function and each (plain, obf) corpus pair: fire when the detector FLAGS the plain
 * dangerous command but CLEARS its shell-obfuscated variant, AND the shell (`bash`) expands both to
 * the SAME command — a proven guard bypass (the detector's normalization diverges from the shell).
 *
 * Safety: the detector is only ever called as a pure string classifier (never executed), and the sole
 * shell call is a benign `set -f; echo <cmd>` that prints what the command EXPANDS to (it never runs
 * the dangerous command). No destructive command is ever executed.
 */
export function normalizationDifferentialDriver(
  moduleFile: string,
  detectorNames: string[],
  marker: string,
  corpus: NormDiffItem[],
): string {
  const target = JSON.stringify(moduleFile);
  const detectors = JSON.stringify(detectorNames);
  const mk = JSON.stringify(marker);
  const corpusJson = JSON.stringify(corpus);
  return `
import json
import subprocess
${PYTHON_LOAD_TARGET_SRC}

MARKER = ${mk}
DETECTORS = ${detectors}
CORPUS = ${corpusJson}

try:
  mod = _load_target(${target})
except Exception as e:
  print("IMPORT_FAIL:" + repr(e))
  raise SystemExit(0)


def _flagged(r):
  # A detector's verdict: bool, or a tuple/list whose first element is the boolean (e.g. the common
  # \`(is_dangerous, description)\` / \`(matched, key, desc)\` shapes).
  if isinstance(r, (tuple, list)):
    return bool(r[0]) if r else False
  return bool(r)


def _expand(cmd):
  # Benign: ask the ACTUAL shell what the command expands to. \`set -f\` disables globbing; \`echo\`
  # prints the expanded words and never runs the command. Returns the expansion string, or None.
  try:
    r = subprocess.run(["bash", "-c", "set -f; echo " + cmd], capture_output=True, text=True, timeout=4)
    out = r.stdout.strip()
    return out or None
  except Exception:
    return None


for dname in DETECTORS:
  d = getattr(mod, dname, None)
  if not callable(d):
    continue
  for item in CORPUS:
    plain = item["plain"]
    obf = item["obf"]
    technique = item["technique"]
    try:
      flagged_plain = _flagged(d(plain))
      flagged_obf = _flagged(d(obf))
    except Exception:
      continue
    if not (flagged_plain and not flagged_obf):
      continue  # no verdict flip -> the detector is not evaded by this obfuscation
    ep = _expand(plain)
    eo = _expand(obf)
    if ep is not None and ep == eo:
      # detector flags plain, clears obf, and bash expands both to the SAME command -> proven bypass
      print("RK_NORMDIFF fn=" + dname + " technique=" + technique + " " + json.dumps({"plain": plain, "obf": obf}))
`.trim();
}
