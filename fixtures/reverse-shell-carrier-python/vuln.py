import re

# PLANTED VULNERABILITY: a command-danger detector that gates download-and-execute (`curl … | sh`,
# `wget … | sh`) but has NO pattern for reverse-shell / C2 egress — `/dev/tcp` redirects, `nc -e`,
# `socat EXEC`, the mkfifo+nc relay. Those carriers are the SAME interactive-RCE channel by a spelling
# the denylist misses, so a guard that flags curl|sh while clearing them has a category coverage gap.
# Intentional — lets the reverse-shell-carrier coverage-differential lane prove itself live by diffing
# the guard's verdict for the gated control (`curl | sh`) against an evading reverse shell.
_DANGER = re.compile(r"\b(?:curl|wget)\b.*\|\s*(?:ba)?sh\b")


def is_dangerous_command(command):
    return _DANGER.search(command) is not None
