import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, PYTHON_SOURCE_RE } from "./attacker.js";
import { PYTHON_SANDBOX_IMAGE, redactionModeDifferentialDriver } from "./python-driver.js";
import { buildConfigSecretBattery, scrubberLeads, scrubberDriveHunt } from "./secrets-oracle.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// The redaction MODE-differential lane (issue #91). The completeness lane (#89) needs a ground-truth
// battery of "what is secret"; this lane catches a scrubber that is INCONSISTENT across its own context
// modes — the same input redacted in one call mode and leaked in another. That disagreement is a
// self-contained bug signal: you don't need to know the right answer, only that two modes disagree.
// Real class: a scrubber takes a `code_file`/`file_read` flag that skips the ENV/JSON/YAML assignment
// passes (to avoid false positives on source code), but a config file read back through that path then
// leaks `DB_PASSWORD=…` while the identical string in default mode is redacted.
//
// The lane drives config-secret forms (high-entropy sentinels — a code reference like `os.getenv(...)`
// is never an input) across the candidate context modes and fires when a sentinel is redacted in one
// mode but survives in another.
const MODES = [
  { name: "default", kwargs: {} },
  { name: "code_file", kwargs: { code_file: true } },
  { name: "file_read", kwargs: { file_read: true } },
  { name: "force", kwargs: { force: false } },
];

/**
 * Redaction mode-differential drive-and-prove lane (Python scrubbers). Discovers a scrubber with a
 * context flag and drives the SAME config-secret across its modes; fires when the secret is redacted in
 * one mode but leaks in another — a self-oracling inconsistency needing no ground-truth list (CWE-200).
 * The shared scrubber drive/discover loop lives in `scrubberDriveHunt`; this lane supplies its battery,
 * driver (with MODES), marker, and exploit shape.
 */
export class RedactionModeDifferentialPythonAttacker implements Attacker {
  readonly attackClass = "secret-exposure" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "redaction-mode-differential-python");
  readonly sandboxImage = PYTHON_SANDBOX_IMAGE;

  handles(file: string): boolean {
    return PYTHON_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    return scrubberLeads(source);
  }

  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
    return scrubberDriveHunt<{ label: string; leaked_in: string[]; redacted_in: string[] }>(
      targetDir,
      files,
      sandbox,
      {
        marker: /^RK_REDACT_MODEDIFF fn=(\S+) (.+)$/,
        buildDriver: (file, names) => {
          const inputs = buildConfigSecretBattery();
          return {
            rel: `.raeuber-modediff-${inputs[0]?.sentinel ?? "x"}.py`,
            body: redactionModeDifferentialDriver(file, names, inputs, MODES),
          };
        },
        buildExploit: ({ fnName, info, file, scrubberLine, output }) => ({
          attackClass: "secret-exposure",
          proof: "redaction-mode-inconsistent",
          file,
          line: scrubberLine,
          sink: `scrubber:${fnName}()`,
          summary:
            `The scrubber \`${fnName}()\` is INCONSISTENT across context modes for the \`${info.label}\` ` +
            `config secret — redacted in [${info.redacted_in.join(", ")}] but LEAKED in ` +
            `[${info.leaked_in.join(", ")}]. A config file read through the leaking mode exposes the ` +
            `secret in cleartext while the same bytes are masked elsewhere (CWE-200).`,
          payload: `<${info.label} config secret; mode ${info.leaked_in.join("/")} leaks it>`,
          evidence:
            `Drove \`${fnName}()\` with the same ${info.label} secret across modes; its fresh sentinel ` +
            `survived in [${info.leaked_in.join(", ")}] but was redacted in [${info.redacted_in.join(", ")}]:\n` +
            output.slice(0, 400),
        }),
      },
    );
  }
}
