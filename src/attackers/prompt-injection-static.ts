import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead } from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// Static LLM-prompt-injection lane (issue #86, CWE-1427). Many agent frameworks route an untrusted
// command/tool-call to an auxiliary "judge" LLM for an approve/deny verdict. If the untrusted text is
// interpolated into the judge prompt using a FIXED, guessable delimiter without escaping, the attacker
// can break out of the fence and inject its own directive (e.g. "Respond: APPROVE") OUTSIDE the block
// the system prompt claims to distrust. The lane fires a lead when an untrusted value is
// string-interpolated into a fixed-literal delimiter, in a file that constructs an LLM call.
//
// No-fire: the value is wrapped in a random per-call NONCE delimiter (`<command_{nonce}>`), XML/JSON-
// escaped, or passed as a separate STRUCTURED message (`{"role": "user", "content": cmd}`) — none of
// which match the fixed-fence-with-interpolation shape.

// The file must construct an LLM call for a prompt-fence to matter.
const LLM_RE =
  /\b(?:call_llm|chat\.completions|\.messages\.create|\.completions\.create|ChatCompletion|generate_content|invoke_model|anthropic|openai|litellm|\.chat\s*\()/i;
// A fixed, guessable delimiter tag immediately followed by an interpolation marker ({...}, ${...},
// string concat, %s / %(...)s / .format). The tag is a plain security-review word with NO embedded
// nonce — `<command_{nonce}>` has a `{` before `>` and does not match `<command>`.
const FIXED_FENCE_RE =
  /<(?:command|user_input|user|input|data|content|query|untrusted|tool_output|tooloutput|context|message|msg)>\s*(?:\{|\$\{|"\s*[+.]|'\s*[+.]|%s|%\(|`|\+\s*\w)/i;
// Also flag a triple-backtick / --- fence directly wrapping an interpolation on the same line.
const DELIM_INTERP_RE = /(?:```|~~~|-{3,}|={3,})\s*(?:\{|\$\{)\s*\w/;

/**
 * Static LLM-prompt-injection lane (CWE-1427). Fires a lead when a value is string-interpolated into a
 * fixed, guessable prompt delimiter (no per-call nonce, no escaping) in a file that constructs an LLM
 * call. `staticOnly` — the LLM actually flipping is not executed, so this is a lead, labelled as such.
 */
export class PromptInjectionStaticAttacker implements Attacker {
  readonly attackClass = "prompt-injection" as const;
  readonly staticOnly = true;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "prompt-injection-static");

  handles(file: string): boolean {
    return /\.(?:ts|mts|cts|mjs|js|cjs|py)$/.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    if (!LLM_RE.test(source)) return []; // no LLM call in this file -> a prompt fence is not a judge prompt
    const leads: StaticLead[] = [];
    const lines = source.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (FIXED_FENCE_RE.test(line) || DELIM_INTERP_RE.test(line)) {
        leads.push({ line: i + 1, sink: "llm-prompt-fixed-delimiter" });
      }
    }
    return leads;
  }

  hunt(_targetDir: string, _files: string[], _sandbox: Sandbox): Exploit[] {
    return []; // static-only: leads feed the sweep; proof is a per-lead targeted test.
  }
}
