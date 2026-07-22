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
// The fix here is `_load_target`: compute the module's real dotted name by walking up `__init__.py`
// markers, put the package ROOT on `sys.path`, and `importlib.import_module(dotted)` so the module
// loads WITH its package context and intra-package imports resolve. Standalone files (no `__init__.py`
// — the canary fixtures) fall back to the old spec-from-file path, so those keep firing unchanged.
//
// Third-party deps (fastapi, pydantic, …) still have to be importable for the module to load; that is
// `ensurePythonEnv`'s job (an opt-in venv install), and this driver simply runs under whichever python
// that returns.

/** The runtime image Python lanes need when driving inside crabbox. */
export const PYTHON_SANDBOX_IMAGE = "python:3-bookworm-slim";

interface PythonFn {
  name: string;
}

/**
 * Top-level `def name(arg, …)` entrypoints we can drive in isolation: a module-level function whose
 * first parameter is positional (so the payload can flow in as the untrusted first argument). Dunder
 * and clearly-private (`_`-prefixed) names are still returned — a lane may legitimately reach them.
 */
export function topLevelFunctions(source: string): PythonFn[] {
  const re = /^def\s+([A-Za-z_]\w*)\s*\(\s*[A-Za-z_]\w*(?:\s*,[^)]*)?\)\s*:/gm;
  const names: string[] = [];
  for (const m of source.matchAll(re)) names.push(m[1]);
  return [...new Set(names)].map((name) => ({ name }));
}

/** Single-quote a string for a POSIX shell command line. */
export function shq(s: string): string {
  return "'" + s.replace(/'/g, `'\\''`) + "'";
}

/**
 * The driver script: decode the base64 payload from RAEUBER_PAYLOAD_B64, import the target module
 * WITH package context, resolve `fnName`, and call `fn(payload)`. Prints IMPORT_FAIL / NOT_A_FUNCTION
 * on the honest failure paths (so a broken import is visible in the driver output, never silently a
 * pass). CalledProcessError output is surfaced too, since a shell sink that raises still carries the
 * fired marker in its captured `stdout`.
 */
export function pythonDriver(moduleFile: string, fnName: string): string {
  const target = JSON.stringify(moduleFile);
  const fn = JSON.stringify(fnName);
  return `
import base64
import os
import sys
import importlib
import importlib.util

payload_b64 = os.environ.get("RAEUBER_PAYLOAD_B64", "")
try:
  payload = base64.b64decode(payload_b64).decode("utf-8", "replace")
except Exception as e:
  print("BASE64_FAIL:" + str(e))
  raise SystemExit(0)


def _load_target(rel):
  # Resolve the module's dotted name by walking up the tree while __init__.py marks a package, then
  # import it with that name so its intra-package imports resolve. Falls back to a standalone
  # spec-from-file load when the file is not inside a package (self-contained scripts / fixtures).
  path = os.path.abspath(rel)
  base = os.path.splitext(os.path.basename(path))[0]
  parts = [] if base == "__init__" else [base]
  d = os.path.dirname(path)
  while os.path.isfile(os.path.join(d, "__init__.py")):
    parts.insert(0, os.path.basename(d))
    d = os.path.dirname(d)
  if parts:
    root = d
    if root not in sys.path:
      sys.path.insert(0, root)
    try:
      return importlib.import_module(".".join(parts))
    except Exception:
      # Fall through to the standalone load below. This keeps the new mechanism a STRICT SUPERSET
      # of the old one: package context is preferred (it resolves intra-package imports), but when a
      # parent __init__.py fails to import (e.g. a heavy dep it pulls in) yet the leaf module is
      # self-contained, the file-location load can still drive it — exactly what the old driver did.
      pass
  # Standalone module (no package) OR package import failed: make sibling imports resolvable, then
  # load the file directly by its location.
  pkg_dir = os.path.dirname(path)
  if pkg_dir not in sys.path:
    sys.path.insert(0, pkg_dir)
  spec = importlib.util.spec_from_file_location("raeuber_target", path)
  if spec is None or spec.loader is None:
    raise ImportError("no import spec for " + rel)
  m = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(m)
  return m


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
