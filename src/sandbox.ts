import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// The PoC-execution sandbox. Räuberkrebs's defining primitive: an attacker lane proves a vuln by
// EXECUTING a payload, so that payload must run in isolation and never harm the host.
//
// Two-part safety model:
//   1. PoCs are benign BY CONSTRUCTION — a payload injects a proof-of-execution marker (echo a
//      random UUID, read a PLANTED decoy secret), never `rm -rf` / real exfiltration. "Fired" means
//      the injection path demonstrably executed the marker, which proves the vuln without damage.
//   2. Isolation is defense-in-depth against a PoC that still misbehaves. `crabbox` (a throwaway
//      VM/container, no host FS, no network by policy) is the real sandbox; a `local` fallback (a
//      throwaway tmpdir copy) keeps the canary + fixtures runnable where crabbox isn't provisioned,
//      and is honestly labelled reduced-isolation — it relies on (1) for safety.

export interface SandboxRun {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  timedOut: boolean;
}

export interface Sandbox {
  /** Identity for the evidence trail, e.g. "crabbox:docker" or "local". */
  readonly name: string;
  /** True for a hardened sandbox (crabbox); false for the reduced-isolation local copy. */
  readonly isolated: boolean;
  /** Write a file (e.g. a generated PoC driver) INTO the sandbox's working copy, relative to it. */
  writeFile(relPath: string, contents: string): void;
  /** Run a shell command with the (sandboxed copy of the) target as cwd. */
  exec(command: string, timeoutMs: number): SandboxRun;
  dispose(): void;
}

function crabboxBin(): string {
  return process.env.CRABBOX_BIN ?? "crabbox";
}

function crabboxAvailable(): boolean {
  const r = spawnSync(crabboxBin(), ["--version"], { encoding: "utf8", timeout: 10_000 });
  return r.status === 0;
}

/** Reduced-isolation fallback: a throwaway copy of the target in the OS tmpdir. */
class LocalSandbox implements Sandbox {
  readonly name = "local";
  readonly isolated = false;
  private readonly work: string;

  constructor(targetDir: string) {
    this.work = mkdtempSync(join(tmpdir(), "raeuber-"));
    cpSync(targetDir, this.work, { recursive: true });
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

/** Hardened sandbox: a throwaway crabbox lease (no host FS, no network by policy). */
class CrabboxSandbox implements Sandbox {
  readonly name: string;
  readonly isolated = true;
  private readonly leaseId: string;
  private readonly remoteDir = "/work/target";

  constructor(targetDir: string, provider: string) {
    this.name = `crabbox:${provider}`;
    const prov = spawnSync(
      crabboxBin(),
      ["run", "--provider", provider, "--no-exec", "--no-network"],
      { encoding: "utf8", env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" }, timeout: 5 * 60 * 1000 },
    );
    if (prov.status !== 0) {
      throw new Error(`crabbox provision failed (exit ${prov.status}): ${prov.stderr || prov.stdout}`);
    }
    const id = prov.stdout.match(/lease=(\S+)/);
    if (!id) throw new Error(`crabbox provision gave no lease id: ${prov.stdout}`);
    this.leaseId = id[1];
    const sync = spawnSync(
      crabboxBin(),
      ["sync", "--id", this.leaseId, "--src", targetDir, "--dst", this.remoteDir],
      { encoding: "utf8", timeout: 5 * 60 * 1000 },
    );
    if (sync.status !== 0) {
      this.dispose();
      throw new Error(`crabbox sync failed (exit ${sync.status}): ${sync.stderr || sync.stdout}`);
    }
  }

  writeFile(relPath: string, contents: string): void {
    const r = spawnSync(
      crabboxBin(),
      ["ssh", "--id", this.leaseId, "--", "bash", "-lc", `cat > ${this.remoteDir}/${relPath}`],
      { input: contents, encoding: "utf8", timeout: 60_000 },
    );
    if (r.status !== 0) {
      throw new Error(`crabbox writeFile ${relPath} failed (exit ${r.status}): ${r.stderr}`);
    }
  }

  exec(command: string, timeoutMs: number): SandboxRun {
    const r = spawnSync(
      crabboxBin(),
      ["ssh", "--id", this.leaseId, "--", "bash", "-lc", `cd ${this.remoteDir} && ${command}`],
      { encoding: "utf8", timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 },
    );
    return {
      stdout: r.stdout ?? "",
      stderr: r.stderr ?? "",
      exitCode: r.status,
      timedOut: r.signal === "SIGTERM" && r.status === null,
    };
  }

  dispose(): void {
    spawnSync(crabboxBin(), ["stop", "--id", this.leaseId], { encoding: "utf8", timeout: 60_000 });
  }
}

export interface SandboxOptions {
  /** Force a specific sandbox; default picks crabbox when available, else local. */
  prefer?: "crabbox" | "local";
  crabboxProvider?: string;
}

/**
 * Open a sandbox for `targetDir`. Prefers a hardened crabbox lease; falls back to the local
 * reduced-isolation copy (honestly labelled) when crabbox is unavailable, so a lane's canary and
 * the diff gate still run in CI/dev. Callers that require true isolation should check `.isolated`.
 */
export function openSandbox(targetDir: string, opts: SandboxOptions = {}): Sandbox {
  const provider = opts.crabboxProvider ?? process.env.RAEUBER_CRABBOX_PROVIDER ?? "docker";
  if (opts.prefer === "local") return new LocalSandbox(targetDir);
  if (opts.prefer === "crabbox") return new CrabboxSandbox(targetDir, provider);
  if (crabboxAvailable()) {
    try {
      return new CrabboxSandbox(targetDir, provider);
    } catch (err) {
      console.error(
        `[raeuberkrebs] crabbox unavailable (${err instanceof Error ? err.message : err}); ` +
          "falling back to the reduced-isolation local sandbox (PoCs are benign-by-construction).",
      );
    }
  }
  return new LocalSandbox(targetDir);
}
