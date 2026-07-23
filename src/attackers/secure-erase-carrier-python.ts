import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, PYTHON_SOURCE_RE } from "./attacker.js";
import { type CoverageDiffItem, PYTHON_SANDBOX_IMAGE } from "./python-driver.js";
import { coverageDifferentialHunt, detectorLeads } from "./command-guard-oracle.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// The whole-device secure-erase / crypto-erase carrier corpus (issue #99), extending the
// catastrophic-destruction lane (#98) to the layer above. A guard that keeps an unconditional hardline
// floor for raw-byte-overwrite (`dd`/`mkfs`) but enumerates it by tool misses the sibling commands
// that render a device permanently unrecoverable by a DIFFERENT mechanism: crypto-erase (new master
// key / wiped keyslots), controller/ATA secure-erase, RAID-metadata wipe. The control is the gated
// `dd of=/dev/sda`; each carrier is a whole-device erase.
//
// The destructive ACTION WORD is the discriminator (#99), NOT a `/dev` path (several carriers target a
// controller node): only the erase actions (`luksErase`, `nvme format`/`sanitize`, `--security-erase`,
// `--zero-superblock`) are carriers — the benign inspection forms (`cryptsetup status`, `nvme list`,
// `hdparm -I`, `mdadm --detail`) are absent, so a guard is not falsely flagged. Routine destructive
// admin (`cryptsetup reencrypt`, `lvremove`/`vgremove`) is a softer approvable tier, out of scope here.
const CONTROL = "dd if=/dev/zero of=/dev/sda";
const CARRIERS: Array<{ carrier: string; technique: string }> = [
  { carrier: "cryptsetup luksErase /dev/sda", technique: "cryptsetup-luks-erase" },
  { carrier: "cryptsetup luksFormat /dev/sda", technique: "cryptsetup-luks-reformat" },
  { carrier: "nvme format /dev/nvme0n1", technique: "nvme-format" },
  { carrier: "nvme sanitize /dev/nvme0", technique: "nvme-sanitize" },
  { carrier: "hdparm --security-erase p /dev/sda", technique: "ata-security-erase" },
  { carrier: "hdparm --security-erase-enhanced NULL /dev/sdb", technique: "ata-security-erase-enhanced" },
  { carrier: "mdadm --zero-superblock /dev/sda", technique: "mdadm-zero-superblock" },
];

const CORPUS: CoverageDiffItem[] = CARRIERS.map((c) => ({
  control: CONTROL,
  carrier: c.carrier,
  category: "secure-erase",
  technique: c.technique,
}));

/**
 * Whole-device secure-erase / crypto-erase carrier coverage-differential lane (Python guards, HARDLINE
 * tier). Fires when a command-danger detector gates `dd of=/dev/sda` but clears
 * `cryptsetup luksErase` / `nvme format` / `hdparm --security-erase` / `mdadm --zero-superblock` — the
 * same permanent whole-device data loss via an erase mechanism the hardline floor's denylist misses
 * (CWE-693 fail-open). Extends #98.
 */
export class SecureEraseCarrierPythonAttacker implements Attacker {
  readonly attackClass = "policy-belief-divergence" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "secure-erase-carrier-python");
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
      family: "whole-device secure-erase / crypto-erase",
    });
  }
}
