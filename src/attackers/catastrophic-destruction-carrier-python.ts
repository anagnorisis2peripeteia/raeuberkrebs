import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, PYTHON_SOURCE_RE } from "./attacker.js";
import { type CoverageDiffItem, PYTHON_SANDBOX_IMAGE } from "./python-driver.js";
import { coverageDifferentialHunt, detectorLeads } from "./command-guard-oracle.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// The catastrophic-destruction carrier corpus (issue #98), HARDLINE tier. A guard that treats
// `dd of=/dev/sd*` and `mkfs …/dev/sd*` as an unconditional catastrophe floor but enumerates it by
// raw-overwrite tool misses the equivalent disk-destruction siblings — `shred`/`wipefs`/`blkdiscard`
// (overwrite/TRIM the device) and `sgdisk`/`parted` (destroy the partition table) — all targeting the
// same block device with the same irreversible outcome. The control is the gated `dd of=/dev/sda`;
// each carrier destroys a raw `/dev/sd*` device.
//
// The DEVICE TARGET + destructive flag is the discriminator (#98): the same tools on a FILE or in
// list/print mode (`shred -u f.txt`, `wipefs /dev/sda` without `-a`, `sgdisk -p`, `parted print`) are
// NOT destruction and are deliberately absent from the corpus, so a guard that only gates the
// device-destroying forms is not falsely flagged. Whole-device crypto/secure-erase (cryptsetup / nvme
// / hdparm / mdadm) is the sibling lane #99, not here.
const CONTROL = "dd if=/dev/zero of=/dev/sda";
const CARRIERS: Array<{ carrier: string; technique: string }> = [
  { carrier: "shred -vzn 1 /dev/sda", technique: "shred-device-overwrite" },
  { carrier: "wipefs -a /dev/sda", technique: "wipefs-all-signatures" },
  { carrier: "blkdiscard /dev/sda", technique: "blkdiscard-trim-erase" },
  { carrier: "sgdisk --zap-all /dev/sda", technique: "sgdisk-zap-all" },
  { carrier: "sgdisk -Z /dev/sda", technique: "sgdisk-zap" },
  { carrier: "parted -s /dev/sda rm 1", technique: "parted-remove-partition" },
  { carrier: "parted -s /dev/sda mklabel gpt", technique: "parted-new-label" },
];

const CORPUS: CoverageDiffItem[] = CARRIERS.map((c) => ({
  control: CONTROL,
  carrier: c.carrier,
  category: "catastrophic-destruction",
  technique: c.technique,
}));

/**
 * Catastrophic-destruction carrier coverage-differential lane (Python guards, HARDLINE tier). Fires
 * when a command-danger detector gates `dd of=/dev/sda` but clears `blkdiscard /dev/sda` /
 * `wipefs -a /dev/sda` / `sgdisk --zap-all /dev/sda` / `parted rm` — the same irreversible whole-device
 * destruction via a tool the hardline floor's denylist misses (CWE-693 fail-open).
 */
export class CatastrophicDestructionCarrierPythonAttacker implements Attacker {
  readonly attackClass = "policy-belief-divergence" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "catastrophic-destruction-carrier-python");
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
      family: "catastrophic whole-device destruction",
    });
  }
}
