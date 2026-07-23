import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead } from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// Untrusted search path (issue #101, CWE-426). The command-injection lane catches shell-metacharacter
// sinks; this lane catches the case where the command NAME is fixed and legitimate but its RESOLUTION
// is attacker-controllable — a process launched from a BARE name (`spawn("codex")`,
// `Command::new("git")`, `subprocess.run(["rg", …])`, `exec.Command("tmux")`, `which(x)`) resolved via
// $PATH/CWD with no trusted-location gate. A local attacker (or a prompt-injected agent) who writes a
// same-named file to an earlier $PATH directory gets code execution in the trusted process. The LOOKUP
// is the sink — there is no metacharacter, so command-injection never sees it.
//
// A static lead, language-agnostic across the languages raeuberkrebs reads. Only a BARE-NAME string
// literal is flagged: an absolute path (`/usr/bin/git`), a `./relative` path, or a variable program
// argument does NOT match (an absolute/trusted-dir launch is the documented no-fire; a variable program
// is command-injection's concern). The name must look like a program token, not a flag or a path.
const SINK_RE = new RegExp(
  [
    // Node child_process: spawn/exec/execFile("bare", …) and spawnSync/execFileSync
    String.raw`\b(?:spawn|exec|execFile|spawnSync|execFileSync)\s*\(\s*["'\x60]([A-Za-z][\w.-]*)["'\x60]`,
    // Node/Python which(x) resolvers with a bare-name literal
    String.raw`\b(?:which|lookpath)\s*\(\s*["'\x60]([A-Za-z][\w.-]*)["'\x60]`,
    // Python subprocess list form: subprocess.run(["bare", …]) / Popen / call / check_output / check_call
    String.raw`\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\(\s*\[\s*["']([A-Za-z][\w.-]*)["']`,
    // Python os.spawnlp/execlp/execvp/spawnvp (the *p variants do a $PATH search by design)
    String.raw`\bos\.(?:exec|spawn)[lv]p\w*\s*\(\s*["']([A-Za-z][\w.-]*)["']`,
    // Go: exec.Command("bare", …) and exec.LookPath("bare")
    String.raw`\bexec\.(?:Command|CommandContext|LookPath)\s*\((?:[^,]*,\s*)?"([A-Za-z][\w.-]*)"`,
    // Rust: Command::new("bare") and which::which("bare")
    String.raw`\b(?:Command::new|which::which)\s*\(\s*"([A-Za-z][\w.-]*)"`,
  ].join("|"),
);

/**
 * Static untrusted-search-path lane (CWE-426). Contributes `staticLeads` to the free sweep: a process
 * launch whose program is a bare name resolved via $PATH/CWD, with no trusted-location gate — a
 * same-named binary planted earlier on $PATH executes unverified. `staticOnly`, so the execute-gate
 * skips it; proof is per-lead (the resolution is filesystem/PATH-dependent, not a driveable sink).
 */
export class UntrustedSearchPathAttacker implements Attacker {
  readonly attackClass = "untrusted-search-path" as const;
  readonly staticOnly = true;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "untrusted-search-path");

  handles(file: string): boolean {
    return /\.(?:ts|mts|cts|mjs|js|cjs|py|go|rs)$/.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    const leads: StaticLead[] = [];
    const lines = source.split("\n");
    for (let i = 0; i < lines.length; i++) {
      // Skip an absolute or ./ relative program — a trusted-location launch is the documented no-fire.
      const m = lines[i].match(SINK_RE);
      if (!m) continue;
      const name = m.slice(1).find(Boolean);
      // A bare program token only: reject anything path-shaped or flag-shaped (already excluded by the
      // regex, but keep the guard explicit for the sink label).
      if (!name || name.startsWith("-")) continue;
      leads.push({ line: i + 1, sink: `bare-launch:${name}` });
    }
    return leads;
  }

  hunt(_targetDir: string, _files: string[], _sandbox: Sandbox): Exploit[] {
    return []; // static-only: leads feed the sweep; proof is a per-lead targeted test.
  }
}
