import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead } from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// Insecure default (issue #103, CWE-1188, often amplifying CWE-347/CWE-306). A codebase can contain a
// perfectly good verifier (signature check, allowlist, sandbox, encryption) whose config DEFAULT is the
// off value, so an out-of-the-box deployment gets no protection and the gate that would stop a
// malicious input is never on the path. This lane flags the default posture: a security-control config
// field whose default is the disabled/off/permissive value.
//
// Three shapes: (A) a verification/auth/TLS field defaulting to false/disabled/off/none; (B) an
// allow/skip/disable/insecure-named field defaulting to true (polarity inverted — TRUE is the insecure
// default there, so `allow_unsigned = false` is CORRECT and must NOT fire); (C) a security-named enum
// default set to a Disabled/Off/None variant. An enforcing default (strict / permissive / true for a
// verify field) does not match. Honest output: a static lead about the DEFAULT POSTURE, not a fired
// exploit — pair with a sink lane to show what the disabled control would have stopped.
const OFF = String.raw`(?:false|["']?disabled["']?|["']?off["']?|["']?none["']?|["']?insecure["']?)`;
const SECFIELD = String.raw`(?:require_auth|auth_required|verify_\w+|\w*_verification|signature_mode|signing_\w*|tls_verify|ssl_verify|verify_tls|verify_ssl|verify_certs?|cert_verification|integrity_check|attestation|sandbox_enabled|csrf_protection|require_\w*(?:auth|sign|tls|cert))`;
const FIELD_OFF_RE = new RegExp(String.raw`(?<![\w.])${SECFIELD}\s*[:=]\s*${OFF}(?![\w])`, "i");
const ALLOW_ON_RE =
  /\b(?:allow_unsigned|allow_insecure|skip_\w*(?:verif|sign|auth|cert|tls)|disable_\w*(?:verif|sign|auth|cert|tls|ssl)|insecure_skip_verify)\s*[:=]\s*(?:true|True)\b/i;
const ENUM_OFF_RE =
  /\b\w*(?:Signature|Verification|Verify|Auth|Tls|Ssl|Encrypt|Sandbox|Security|Cert)\w*(?:Mode|Level|Policy)?::(?:Disabled|Off|None|Insecure|Unverified)\b/i;

/**
 * Static insecure-default lane (CWE-1188). Fires a lead when a security control's config default is the
 * disabled/off value: a verify/auth/TLS/signature field defaulting to false/disabled, an
 * allow/skip/disable-named field defaulting to true, or a security enum default set to Disabled/Off.
 * `staticOnly`; the lead names the default posture, not a fired exploit.
 */
export class InsecureDefaultAttacker implements Attacker {
  readonly attackClass = "insecure-default" as const;
  readonly staticOnly = true;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "insecure-default");

  handles(file: string): boolean {
    return /\.(?:ts|mts|cts|mjs|js|cjs|py|go|rs|toml|ya?ml|json|ini|cfg)$/.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    const leads: StaticLead[] = [];
    const lines = source.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (FIELD_OFF_RE.test(line) || ALLOW_ON_RE.test(line) || ENUM_OFF_RE.test(line)) {
        leads.push({ line: i + 1, sink: "insecure-default" });
      }
    }
    return leads;
  }

  hunt(_targetDir: string, _files: string[], _sandbox: Sandbox): Exploit[] {
    return []; // static-only: leads feed the sweep; proof is a per-lead targeted test.
  }
}
