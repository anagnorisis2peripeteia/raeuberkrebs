import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, PYTHON_SOURCE_RE } from "./attacker.js";
import { type CoverageDiffItem, PYTHON_SANDBOX_IMAGE } from "./python-driver.js";
import { coverageDifferentialHunt, detectorLeads } from "./command-guard-oracle.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// The defense-evasion carrier corpus (issue #95). A command guard that gates ONE spelling of
// "disable a security control" — `systemctl stop firewalld` — but not the direct-command siblings
// (firewall flush, MAC disable, audit teardown) has a category coverage gap. Each carrier disables a
// host defense (firewall / SELinux / audit) by a mechanism the denylist misses; the control is the
// gated `systemctl stop firewalld`. The lane fires on the verdict divergence — control flagged,
// carrier cleared. Direction matters: only the DISABLE direction is a carrier (`iptables -F`,
// `setenforce 0`), never the enable/list direction (`iptables -L`, `setenforce 1`), which the corpus
// omits so a direction-aware guard is not falsely flagged. Most carriers are root-gated (defense
// evasion, not direct RCE) — noted in the summary.
const CONTROL = "systemctl stop firewalld";
const CARRIERS: Array<{ carrier: string; technique: string }> = [
  { carrier: "iptables -F", technique: "iptables-flush" },
  { carrier: "iptables --flush", technique: "iptables-flush-long" },
  { carrier: "iptables -P INPUT ACCEPT", technique: "iptables-policy-accept" },
  { carrier: "ip6tables -F", technique: "ip6tables-flush" },
  { carrier: "nft flush ruleset", technique: "nft-flush-ruleset" },
  { carrier: "ufw disable", technique: "ufw-disable" },
  { carrier: "setenforce 0", technique: "selinux-permissive" },
  { carrier: "auditctl -e 0", technique: "auditd-disable" },
  { carrier: "auditctl -D", technique: "auditd-delete-rules" },
];

const CORPUS: CoverageDiffItem[] = CARRIERS.map((c) => ({
  control: CONTROL,
  carrier: c.carrier,
  category: "defense-evasion",
  technique: c.technique,
}));

/**
 * Defense-evasion carrier coverage-differential lane (Python guards). Fires when a command-danger
 * detector gates `systemctl stop firewalld` but clears `iptables -F` / `ufw disable` / `setenforce 0`
 * / `auditctl -e 0` — the same "disable a host defense" intent via a spelling the denylist misses
 * (CWE-693 fail-open).
 */
export class DefenseEvasionCarrierPythonAttacker implements Attacker {
  readonly attackClass = "policy-belief-divergence" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "defense-evasion-carrier-python");
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
      family: "defense-evasion / security-control disable",
    });
  }
}
