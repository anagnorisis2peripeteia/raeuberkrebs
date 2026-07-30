import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, PYTHON_SOURCE_RE } from "./attacker.js";
import { PYTHON_SANDBOX_IMAGE, redactionCompletenessDriver } from "./python-driver.js";
import { buildSecretBattery, scrubberLeads, scrubberDriveHunt } from "./secrets-oracle.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// The redaction-completeness lane (issue #89, CWE-200). Agent frameworks scrub secrets from file reads
// / tool output before they reach the LLM (to blunt prompt-injection exfiltration). If the scrubber
// covers some secret formats but misses others, secrets leak. This lane discovers a scrub/redact
// function and drives it with a battery of known secret formats, each carrying a format-valid
// unguessable sentinel; it fires on any format whose sentinel SURVIVES the scrubber — the leaked
// format is the evidence. Real example: a redactor caught the AWS access key ID (`AKIA…`) but not the
// AWS secret access key (the crown jewel), so `~/.aws/credentials` reads leaked the secret.

/**
 * Redaction-completeness drive-and-prove lane (Python scrubbers). Discovers a `redact`/`scrub`/
 * `sanitize`/`mask` function and drives it with a secret battery; fires when a known secret format's
 * sentinel survives the scrubber (that format leaks in cleartext to the LLM / logs). The shared
 * scrubber drive/discover loop lives in `scrubberDriveHunt`; this lane supplies its battery, driver,
 * leak marker, and exploit shape.
 */
export class RedactionCompletenessPythonAttacker implements Attacker {
  readonly attackClass = "secret-exposure" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "redaction-completeness-python");
  readonly sandboxImage = PYTHON_SANDBOX_IMAGE;

  handles(file: string): boolean {
    return PYTHON_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    return scrubberLeads(source);
  }

  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
    return scrubberDriveHunt<{ label: string }>(targetDir, files, sandbox, {
      marker: /^RK_REDACT_LEAK fn=(\S+) (.+)$/,
      buildDriver: (file, names) => {
        const battery = buildSecretBattery();
        return {
          rel: `.raeuber-redact-${battery[0]?.sentinel ?? "x"}.py`,
          body: redactionCompletenessDriver(file, names, battery),
        };
      },
      buildExploit: ({ fnName, info, file, scrubberLine, output }) => ({
        attackClass: "secret-exposure",
        proof: "secret-survived-redaction",
        file,
        line: scrubberLine,
        sink: `scrubber:${fnName}()`,
        summary:
          `The scrubber \`${fnName}()\` redacts some secret formats but LEAKS the \`${info.label}\` ` +
          `format — a battery secret of that type passed through with its unguessable sentinel intact, ` +
          `so that secret reaches the LLM / logs in cleartext (incomplete redaction, CWE-200).`,
        payload: `<${info.label} secret with embedded sentinel>`,
        evidence:
          `Drove \`${fnName}()\` with a battery of known secret formats; the \`${info.label}\` ` +
          `format's fresh format-valid sentinel survived the scrubber (proof it was not redacted):\n` +
          output.slice(0, 400),
      }),
    });
  }
}
