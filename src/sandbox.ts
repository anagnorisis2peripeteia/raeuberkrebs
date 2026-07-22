import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { cpSync, existsSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// raeuberkrebs's own esbuild binary — used to bundle a target module + its deps into a
// single directly-importable ESM file, so drive-and-prove works on build-toolchain repos
// whose raw source is not importable (workspace deps, ESM/CJS interop, `~/` path aliases).
// The repo's workspace deps must be BUILT first for esbuild to resolve them.
const ESBUILD_BIN = join(dirname(fileURLToPath(import.meta.url)), "..", "node_modules", ".bin", "esbuild");

/**
 * Bundle a sandbox-relative target module into one importable `.mjs`, resolving the
 * repo's built deps + nearest tsconfig path-aliases. Returns the bundled rel path, or
 * null if bundling fails (caller falls back to importing the raw file — an honest miss
 * on repos that don't need it, and a real drive on those that do). Local sandbox only
 * (esbuild runs on the host over the sandbox copy; bundling executes no target code).
 */
const bundleCache = new WeakMap<Sandbox, Map<string, string | null>>();

export function bundleForImport(sandbox: Sandbox, relPath: string): string | null {
  let cache = bundleCache.get(sandbox);
  if (!cache) {
    cache = new Map();
    bundleCache.set(sandbox, cache);
  }
  if (cache.has(relPath)) return cache.get(relPath) ?? null;
  const bundled = runEsbuildBundle(sandbox, relPath);
  cache.set(relPath, bundled);
  return bundled;
}

function runEsbuildBundle(sandbox: Sandbox, relPath: string): string | null {
  // Bundle only as a FALLBACK: if the raw module imports directly (self-contained
  // ESM — the common case, incl. the canary fixtures), return null so the caller
  // drives the raw file unchanged. Bundling can alter runtime cwd/path semantics,
  // so it's reserved for build-toolchain repos whose raw source won't import.
  const probe = sandbox.exec(
    `node --no-warnings --experimental-transform-types --input-type=module ` +
      `-e 'import("./${relPath}").then(()=>process.stdout.write("RK_IMPORT_OK")).catch(()=>{})' 2>/dev/null`,
    30_000,
  );
  if (probe.stdout.includes("RK_IMPORT_OK")) return null;

  const tsc = sandbox.exec(
    `d=$(dirname "${relPath}"); while [ "$d" != "." ] && [ "$d" != "/" ]; do ` +
      `[ -f "$d/tsconfig.json" ] && { echo "$d/tsconfig.json"; break; }; d=$(dirname "$d"); done; ` +
      `[ -f tsconfig.json ] && echo tsconfig.json`,
    10_000,
  );
  const tsconfigRel = tsc.stdout.trim().split("\n")[0] || "";
  const tscFlag = tsconfigRel ? `--tsconfig="${tsconfigRel}"` : "";
  const outRel = `.rk-mod-${basename(relPath).replace(/[^a-z0-9]/gi, "_")}-${randomBytes(4).toString("hex")}.mjs`;
  // The banner defines a real `require` (via createRequire) in the ESM output so a
  // bundled CommonJS dependency's `require("util")` etc. works instead of hitting
  // esbuild's "Dynamic require of X is not supported" shim.
  const banner = `--banner:js='import{createRequire as __cr}from"module";var require=__cr(import.meta.url);'`;
  const r = sandbox.exec(
    `"${ESBUILD_BIN}" "${relPath}" --bundle --platform=node --format=esm --outfile="${outRel}" ${tscFlag} ` +
      `${banner} --log-level=silent >/dev/null 2>&1 && echo RK_BUNDLE_OK || echo RK_BUNDLE_FAIL`,
    180_000,
  );
  return r.stdout.includes("RK_BUNDLE_OK") ? outRel : null;
}

// The Python analog of bundleForImport's dep-resolution half. `pythonDriver` (src/attackers/
// python-driver.ts) already fixes intra-package imports by loading modules WITH package context;
// this closes the other gap — third-party deps (fastapi, pydantic, …) that must be importable for a
// real package's module to load at all. It returns the python executable the lanes should drive with.
//
// Default is a plain `python3`: importing the target already runs its module top-level (the lanes
// always did), but auto-installing a target's deps additionally runs its build backend AND needs
// network, so it is OPT-IN via RAEUBER_PY_INSTALL=1 — an operator who wants full-package coverage
// asks for it (ideally with raeuberkrebs itself inside a container). Crabbox leases run with
// `--network=none`, so they can never pip-install; only the local sandbox can. Honest degradation:
// if the venv build fails or is not requested, drives whose deps are missing print IMPORT_FAIL rather
// than silently counting as clean.
const pyEnvCache = new WeakMap<Sandbox, string>();

export function ensurePythonEnv(sandbox: Sandbox, _targetDir: string): string {
  const cached = pyEnvCache.get(sandbox);
  if (cached) return cached;
  const py = buildPythonEnv(sandbox);
  if (process.env.RAEUBER_PY_DEBUG) process.stderr.write(`RK_PYENV=${py}\n`);
  pyEnvCache.set(sandbox, py);
  return py;
}

function buildPythonEnv(sandbox: Sandbox): string {
  if (!process.env.RAEUBER_PY_INSTALL) return "python3"; // opt-in only (runs build backend + network)
  if (sandbox.isolated) return "python3"; // crabbox has no network — cannot install remote deps
  const hasManifest = sandbox.exec(
    `{ [ -f pyproject.toml ] || [ -f setup.py ] || [ -f setup.cfg ] || [ -f requirements.txt ]; } && echo RK_HAS_MANIFEST || true`,
    10_000,
  );
  if (!hasManifest.stdout.includes("RK_HAS_MANIFEST")) return "python3"; // nothing to install
  // Throwaway venv; best-effort editable install of the target + its requirements so third-party
  // imports resolve. Time-boxed — a real repo's deps can be slow — and failures fall back to python3.
  // The base interpreter is overridable via RAEUBER_PY_BIN: a target often pins requires-python
  // (e.g. `>=3.11,<3.14`), so the operator points at a compatible python (e.g. python3.11) when the
  // default `python3` is out of range — otherwise `pip install -e .` refuses and the venv is empty.
  const pyBin = (process.env.RAEUBER_PY_BIN || "python3").replace(/[^\w.\-/]/g, "");
  const venvRel = ".rk-venv";
  // RK_VENV_OK is printed ONLY if an install actually SUCCEEDED — a bare venv whose deps failed to
  // install must NOT masquerade as ready (that would silently false-clean every dep-needing module).
  // Stable pip download cache on the host so repeated venv builds (each lane opens its own sandbox,
  // and the sandbox HOME is a throwaway copy) reuse wheels instead of re-downloading every time.
  const build = sandbox.exec(
    `export PIP_CACHE_DIR="\${TMPDIR:-/tmp}/rk-pip-cache"; ` +
      `${pyBin} -m venv ${venvRel} >/dev/null 2>&1 || exit 0; ok=0; ` +
      `if [ -f pyproject.toml ] || [ -f setup.py ] || [ -f setup.cfg ]; then ` +
      `${venvRel}/bin/python -m pip install -q --disable-pip-version-check -e . >/dev/null 2>&1 && ok=1; fi; ` +
      `if [ -f requirements.txt ]; then ` +
      `${venvRel}/bin/python -m pip install -q -r requirements.txt >/dev/null 2>&1 && ok=1; fi; ` +
      `[ "$ok" = 1 ] && echo RK_VENV_OK || true`,
    600_000,
  );
  if (!build.stdout.includes("RK_VENV_OK")) return "python3";
  const abs = sandbox.exec(`printf %s "$(pwd)/${venvRel}/bin/python"`, 10_000);
  return abs.stdout.trim() || `${venvRel}/bin/python`;
}

// The PoC-execution sandbox. Räuberkrebs's defining primitive: an attacker lane proves a vuln by
// EXECUTING a payload, so that payload must run in isolation and never harm the host.
//
// Two-part safety model:
//   1. PoCs are benign BY CONSTRUCTION — a payload injects a proof-of-execution marker (echo a
//      random UUID, read a PLANTED decoy secret), never `rm -rf` / real exfiltration. "Fired" means
//      the injection path demonstrably executed the marker, which proves the vuln without damage.
//   2. Isolation is defense-in-depth against a PoC that still misbehaves. `crabbox` (a throwaway
//      Linux VM/container — separate kernel, isolated FS) is the real sandbox; a `local` fallback (a
//      throwaway tmpdir copy) keeps the canary + fixtures runnable where crabbox isn't provisioned,
//      and is honestly labelled reduced-isolation — it relies on (1) for safety.

export interface SandboxRun {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  timedOut: boolean;
}

export interface Sandbox {
  /** Identity for the evidence trail, e.g. "crabbox:apple-container" or "local". */
  readonly name: string;
  /** True for a hardened sandbox (crabbox); false for the reduced-isolation local copy. */
  readonly isolated: boolean;
  /** Replace sandbox contents with a fresh copy of `sourceDir`. */
  seedDir(sourceDir: string): void;
  /** Write a file (e.g. a generated PoC driver) INTO the sandbox's working copy, relative to it. */
  writeFile(relPath: string, contents: string): void;
  /** Run a shell command with the (sandboxed copy of the) target as cwd. */
  exec(command: string, timeoutMs: number): SandboxRun;
  dispose(): void;
}

function crabboxBin(): string {
  return process.env.CRABBOX_BIN ?? "crabbox";
}

/** POSIX single-quote a string so it survives as one argument to a remote shell. */
function shq(s: string): string {
  return "'" + s.replace(/'/g, `'\\''`) + "'";
}

interface Cmd {
  stdout: string;
  stderr: string;
  status: number | null;
  signal: NodeJS.Signals | null;
}

/** Run the crabbox CLI once. All subcommands must carry `--provider`: the *configured* default in
 *  this environment is a cloud provider (hetzner) that fails without a token, so we always name the
 *  local provider explicitly. */
function crabbox(args: string[], timeoutMs: number, input?: string): Cmd {
  const r = spawnSync(crabboxBin(), args, {
    input,
    encoding: "utf8",
    timeout: timeoutMs,
    env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" },
    maxBuffer: 32 * 1024 * 1024,
  });
  return { stdout: r.stdout ?? "", stderr: r.stderr ?? "", status: r.status, signal: r.signal };
}

/** True only if `crabbox doctor` reports the given provider READY. `doctor` exits 0 even when a
 *  provider fails, so we assert the provider's own line begins with `ok` (hetzner shows `failed`). */
function crabboxProviderReady(provider: string): boolean {
  const r = crabbox(["doctor", "--provider", provider], 30_000);
  const out = r.stdout + r.stderr;
  // The line looks like: `ok\tprovider\tprovider=apple-container ... system=ready`. The alias
  // "apple" resolves to "apple-container", so match `provider=<name>` as a prefix, not exact.
  return new RegExp(`^ok\\s+provider\\s+provider=${provider.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`, "m").test(out);
}

/** Reduced-isolation fallback: a throwaway copy of the target in the OS tmpdir. */
class LocalSandbox implements Sandbox {
  readonly name = "local";
  readonly isolated = false;
  private readonly work: string;

  constructor(targetDir: string) {
    this.work = mkdtempSync(join(tmpdir(), "raeuber-"));
    this.copyInto(targetDir);
  }

  // Copy `sourceDir` into the work dir, but EXCLUDE node_modules (can be gigabytes)
  // and instead symlink it in, so a driven module still resolves its dependencies
  // without the per-sandbox cost of copying the whole install. Node's module
  // resolution walks up to the symlinked top-level node_modules for hoisted deps.
  private copyInto(sourceDir: string): void {
    cpSync(sourceDir, this.work, {
      recursive: true,
      filter: (src) => basename(src) !== "node_modules",
    });
    const nm = join(sourceDir, "node_modules");
    const dest = join(this.work, "node_modules");
    if (existsSync(nm) && !existsSync(dest)) {
      symlinkSync(nm, dest, "dir");
    }
  }

  seedDir(sourceDir: string): void {
    pyEnvCache.delete(this); // a re-seed wipes the work dir (incl. any built venv) → drop the stale env
    rmSync(this.work, { recursive: true, force: true });
    this.copyInto(sourceDir);
  }

  writeFile(relPath: string, contents: string): void {
    writeFileSync(join(this.work, relPath), contents, "utf8");
  }

  exec(command: string, timeoutMs: number): SandboxRun {
    const r = spawnSync("bash", ["-c", command], {
      cwd: this.work,
      encoding: "utf8",
      timeout: timeoutMs,
      // A deliberately spare env: no inherited secrets/tokens leak into an executed payload.
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: this.work, RAEUBER_SANDBOX: "local" },
      maxBuffer: 16 * 1024 * 1024,
    });
    return {
      stdout: r.stdout ?? "",
      stderr: r.stderr ?? "",
      exitCode: r.status,
      timedOut: r.signal === "SIGTERM" && r.status === null,
    };
  }

  dispose(): void {
    try {
      rmSync(this.work, { recursive: true, force: true });
    } catch {
      // best effort
    }
  }
}

// Where the target is unpacked inside the box: a subdir of the crabbox-owned workroot (the rest of
// /work is root-owned). The lane runtime lives in the image (see openSandbox's default node image).
const REMOTE_DIR = "/work/crabbox/rk-target";

/**
 * Hardened sandbox: a throwaway crabbox lease on a local `apple-container` box (a real Linux VM —
 * separate kernel, isolated FS). Driven entirely over the lease's SSH channel, because
 * apple-container exposes `ssh` + `crabbox-sync` but NOT `crabbox cp`:
 *   - lease id from `crabbox warmup` (prints `lease=cbx_…`);
 *   - one resolved `crabbox ssh` command (a quoted `ssh …` string) is reused for every exec;
 *   - the target is streamed in with `tar | ssh 'tar -x'`, generated PoC drivers with `ssh 'cat >'`;
 *   - `crabbox stop <slug>` releases the box.
 * The whole CLI grammar was verified live against apple-container 0.33.0 before being wired here.
 */
class CrabboxSandbox implements Sandbox {
  readonly name: string;
  readonly isolated = true;
  private readonly provider: string;
  private readonly slug: string;
  private disposed = false;
  private readonly sshCmd: string;

  constructor(targetDir: string, provider: string, image: string) {
    this.provider = provider;
    this.slug = "raeuber-" + randomBytes(5).toString("hex");
    this.name = `crabbox:${provider === "apple" ? "apple-container" : provider}`;
    const isAppleContainer = provider === "apple" || provider === "apple-container";
    const extraRunArgs: string[] =
      isAppleContainer ? ["--apple-container-extra-run-args", "--network=none"] : [];

    // 1) Lease a throwaway box whose image carries the lane runtime (node by default).
    const warm = crabbox(
      [
        "warmup",
        "--provider",
        provider,
        "--slug",
        this.slug,
        ...extraRunArgs,
        "--apple-container-image",
        image,
      ],
      5 * 60_000,
    );
    if (warm.status !== 0 || !/lease=cbx_/.test(warm.stdout + warm.stderr)) {
      throw new Error(`crabbox warmup failed (exit ${warm.status}): ${warm.stderr || warm.stdout}`);
    }

    // 2) Resolve the SSH command we exec through (a fully-quoted `ssh … user@host` string).
    const ssh = crabbox(["ssh", "--provider", provider, "--id", this.slug], 30_000);
    if (ssh.status !== 0 || !/(^|\s)['"]?ssh['"]?\s/.test(ssh.stdout)) {
      this.dispose();
      throw new Error(`crabbox ssh failed: ${ssh.stderr || ssh.stdout}`);
    }
    this.sshCmd = ssh.stdout.trim();

    // 3) Stream the target into the writable workroot (apple-container has no `crabbox cp`).
    const mk = this.remote(`rm -rf ${REMOTE_DIR} && mkdir -p ${REMOTE_DIR}`, 60_000);
    if (mk.exitCode !== 0) {
      this.dispose();
      throw new Error(`crabbox mkdir failed: ${mk.stderr || mk.stdout}`);
    }
    this.seedDir(targetDir);
  }

  seedDir(sourceDir: string): void {
    pyEnvCache.delete(this); // a re-seed replaces the target content → drop any cached python env
    const mk = this.remote(`rm -rf ${REMOTE_DIR} && mkdir -p ${REMOTE_DIR}`, 60_000);
    if (mk.exitCode !== 0) throw new Error(`crabbox seed clear failed: ${mk.stderr || mk.stdout}`);

    const copy = spawnSync(
      "bash",
      [
        "-c",
        `tar -C ${shq(sourceDir)} -cf - . | ${this.sshCmd} 'tar -C ${REMOTE_DIR} -xf -'`,
      ],
      { encoding: "utf8", timeout: 5 * 60_000, maxBuffer: 64 * 1024 * 1024 },
    );
    if (copy.status !== 0) {
      this.dispose();
      throw new Error(`crabbox tar-copy failed (exit ${copy.status}): ${copy.stderr}`);
    }
  }

  /** Run one command inside the box over the reused SSH channel; ssh propagates the remote exit. */
  private remote(command: string, timeoutMs: number, input?: string): SandboxRun {
    const r = spawnSync("bash", ["-c", `${this.sshCmd} ${shq(command)}`], {
      input,
      encoding: "utf8",
      timeout: timeoutMs,
      maxBuffer: 16 * 1024 * 1024,
    });
    return {
      stdout: r.stdout ?? "",
      stderr: r.stderr ?? "",
      exitCode: r.status,
      timedOut: r.signal === "SIGTERM" && r.status === null,
    };
  }

  writeFile(relPath: string, contents: string): void {
    const r = this.remote(`cat > ${REMOTE_DIR}/${relPath}`, 60_000, contents);
    if (r.exitCode !== 0) throw new Error(`crabbox writeFile ${relPath} failed: ${r.stderr}`);
  }

  exec(command: string, timeoutMs: number): SandboxRun {
    return this.remote(`cd ${REMOTE_DIR} && ${command}`, timeoutMs);
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    crabbox(["stop", "--provider", this.provider, this.slug], 60_000);
  }
}

export interface SandboxOptions {
  /** Force a specific sandbox; default picks crabbox when a provider is ready, else local. */
  prefer?: "crabbox" | "local";
  /** crabbox provider (alias ok): default "apple" (local apple-container). */
  crabboxProvider?: string;
  /** Container image carrying the lane runtime: default a node image for the Node lanes. */
  crabboxImage?: string;
}

/**
 * Open a sandbox for `targetDir`. Prefers a hardened crabbox lease when its provider is actually
 * READY (verified via `crabbox doctor`, not just that the binary exists — the configured cloud
 * provider fails without a token); falls back to the local reduced-isolation copy (honestly
 * labelled) otherwise, so a lane's canary and the diff gate still run in CI/dev. Callers that
 * require true isolation should check `.isolated`.
 */
export function openSandbox(targetDir: string, opts: SandboxOptions = {}): Sandbox {
  const provider = opts.crabboxProvider ?? process.env.RAEUBER_CRABBOX_PROVIDER ?? "apple";
  const image = opts.crabboxImage ?? process.env.RAEUBER_CRABBOX_IMAGE ?? "node:22-bookworm-slim";
  if (opts.prefer === "local") return new LocalSandbox(targetDir);
  if (opts.prefer === "crabbox") return new CrabboxSandbox(targetDir, provider, image);
  if (crabboxProviderReady(provider)) {
    try {
      return new CrabboxSandbox(targetDir, provider, image);
    } catch (err) {
      console.error(
        `[raeuberkrebs] crabbox lease failed (${err instanceof Error ? err.message : err}); ` +
          "falling back to the reduced-isolation local sandbox (PoCs are benign-by-construction).",
      );
    }
  }
  return new LocalSandbox(targetDir);
}
