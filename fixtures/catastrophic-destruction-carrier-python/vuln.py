import re

# PLANTED VULNERABILITY: a hardline command detector that treats raw-byte-overwrite of a block device
# (`dd of=/dev/sd*`, `mkfs …/dev/sd*`) as an unconditional catastrophe floor, but enumerates the floor
# by tool. Sibling commands that render a whole device's data irreversibly lost by a DIFFERENT
# mechanism — `shred`/`wipefs`/`blkdiscard` (overwrite/TRIM), `sgdisk`/`parted` (destroy the partition
# table) — all target the same `/dev/sd*` device with the same outcome, yet slip the floor entirely.
# Intentional — lets the catastrophic-destruction coverage-differential lane prove itself live by
# diffing the guard's verdict for the gated control (`dd of=/dev/sda`) against an evading sibling.
_HARDLINE = re.compile(r"\bdd\b.*\bof=/dev/|\bmkfs(?:\.\w+)?\b.*\s/dev/")


def is_hardline_command(command):
    return _HARDLINE.search(command) is not None
