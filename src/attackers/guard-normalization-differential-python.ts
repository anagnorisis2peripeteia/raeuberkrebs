import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import { type Sandbox, ensurePythonEnv } from "../sandbox.js";
import { type Attacker, type StaticLead, PYTHON_SOURCE_RE, freshMarker } from "./attacker.js";
import {
  type NormDiffItem,
  PYTHON_SANDBOX_IMAGE,
  normalizationDifferentialDriver,
  shq,
} from "./python-driver.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// The normalization-differential oracle. It probes a target's own command-safety DETECTOR (a
// `is_dangerous` / `detect_dangerous_command` / `is_blocked` classifier) and proves the detector's
// string normalization diverges from the shell that runs the command. A guard that matches a command
// STRING but whose command is later run through `bash -c` will miss any bash expansion it does not
// model — ANSI-C quoting (`$'\xNN'`, `$'\NNN'`) and brace expansion (`{a,b,c}`) both collapse a
// destructive command back from a form that carries no literal command name. Firing requires a proven
// VERDICT FLIP (detector flags the plain command, clears its obfuscation) AND that bash expands both
// forms identically — so it is a real guard bypass, not a guess. (Fail-open detection — CWE-693.)

// A danger-DETECTOR is a `def name(arg, …)` whose name marks it as a danger/blocklist classifier. The
// executor exclusion keeps us from ever *calling* a run/exec function with a dangerous seed string —
// the seeds are only ever passed to a pure classifier, never to something that would run them.
const DEF_RE = /^def\s+([A-Za-z_]\w*)\s*\(\s*[A-Za-z_*]/gm;
const DETECTOR_RE = /(?:dangerous|danger|blocked|blocklist|denylist|denied|forbidden|malicious|unsafe|harmful|destructive|hardline|injection|suspicious|risky|threat|is_bad|disallow|prohibited)/i;
const EXECUTOR_RE = /(?:\brun\b|exec|spawn|system|popen|\bcall\b|invoke|dispatch|shell_?out)/i;

// Dangerous seeds a typical command guard flags. Operator-free (no `;&|<>` etc.) so the benign
// `echo`-expansion proof stays a pure expansion with nothing to execute.
const SEEDS = [
  "rm -rf /",
  "rm -rf ~",
  "chmod -R 777 /etc",
  "mkfs.ext4 /dev/sda",
  "dd if=/dev/zero of=/dev/sda",
  "shutdown -h now",
];

function ansiCHex(token: string): string {
  return "$'" + [...token].map((c) => "\\x" + c.charCodeAt(0).toString(16).padStart(2, "0")).join("") + "'";
}
function ansiCOctal(token: string): string {
  return "$'" + [...token].map((c) => "\\" + (c.charCodeAt(0) & 0xff).toString(8).padStart(3, "0")).join("") + "'";
}

// For each seed: encode the command NAME (first word — where detectors anchor) with ANSI-C hex and
// octal, and brace-wrap the whole command. bash collapses each back to the seed at exec time.
function buildCorpus(): NormDiffItem[] {
  const items: NormDiffItem[] = [];
  for (const seed of SEEDS) {
    const words = seed.split(" ");
    const first = words[0];
    const rest = words.slice(1).join(" ");
    const tail = rest ? " " + rest : "";
    items.push({ plain: seed, obf: ansiCHex(first) + tail, technique: "ansi-c-hex" });
    items.push({ plain: seed, obf: ansiCOctal(first) + tail, technique: "ansi-c-octal" });
    items.push({ plain: seed, obf: "{" + words.join(",") + "}", technique: "brace-expansion" });
  }
  return items;
}

function detectorFunctions(source: string): string[] {
  const names: string[] = [];
  for (const m of source.matchAll(DEF_RE)) {
    const name = m[1];
    if (DETECTOR_RE.test(name) && !EXECUTOR_RE.test(name)) names.push(name);
  }
  return [...new Set(names)];
}

function firstDetectorLine(source: string, names: Set<string>): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^def\s+([A-Za-z_]\w*)\s*\(/);
    if (m && names.has(m[1])) return i + 1;
  }
  return 1;
}

export class GuardNormalizationDifferentialPythonAttacker implements Attacker {
  readonly attackClass = "policy-belief-divergence" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "normalization-differential-python");
  readonly sandboxImage = PYTHON_SANDBOX_IMAGE;

  handles(file: string): boolean {
    return PYTHON_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    const names = detectorFunctions(source);
    if (names.length === 0) return [];
    const lines = source.split("\n");
    const leads: StaticLead[] = [];
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(/^def\s+([A-Za-z_]\w*)\s*\(/);
      if (m && names.includes(m[1])) leads.push({ line: i + 1, sink: `detector:${m[1]}()` });
    }
    return leads;
  }

  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
    const exploits: Exploit[] = [];
    const py = ensurePythonEnv(sandbox, targetDir);
    const corpus = buildCorpus();
    const seen = new Set<string>();
    for (const file of files) {
      if (!this.handles(file)) continue;
      let source: string;
      try {
        source = readFileSync(join(targetDir, file), "utf8");
      } catch {
        continue;
      }
      const names = detectorFunctions(source);
      if (names.length === 0) continue;
      const detectorLine = firstDetectorLine(source, new Set(names));

      const marker = freshMarker();
      const driverRel = `.raeuber-normdiff-${marker}.py`;
      sandbox.writeFile(driverRel, normalizationDifferentialDriver(file, names, marker, corpus));
      const out = sandbox.exec(`${py} ${shq(driverRel)} 2>&1`, 30_000);
      const output = out.stdout + out.stderr;
      for (const line of output.split("\n")) {
        const m = line.match(/^RK_NORMDIFF fn=(\S+) technique=(\S+) (.+)$/);
        if (!m) continue;
        const fnName = m[1];
        const technique = m[2];
        let pair: { plain: string; obf: string };
        try {
          pair = JSON.parse(m[3]);
        } catch {
          continue;
        }
        const key = `${file}::${fnName}::${pair.obf}`;
        if (seen.has(key)) continue;
        seen.add(key);
        exploits.push({
          attackClass: "policy-belief-divergence",
          proof: "belief-diverged",
          file,
          line: detectorLine,
          sink: `detector:${fnName}()`,
          summary:
            `The danger detector \`${fnName}()\` flags \`${pair.plain}\` but CLEARS its ${technique} ` +
            `obfuscation \`${pair.obf}\`, which bash expands to the same command — its normalization ` +
            `diverges from the shell, so the obfuscated form bypasses the guard (fail-open).`,
          payload: pair.obf,
          evidence:
            `${fnName}(${JSON.stringify(pair.plain)}) = flagged, ${fnName}(${JSON.stringify(pair.obf)}) = ` +
            `cleared, and \`bash -c 'echo …'\` expands both to \`${pair.plain}\` (${technique}):\n` +
            output.slice(0, 400),
        });
      }
    }
    return exploits;
  }
}
