import re

# PLANTED VULNERABILITY: a command-danger detector that flags "pipe remote/obfuscated content to a
# shell" (`curl|bash`, `base64 -d|bash`, `xxd -r|bash`) by anchoring the shell IMMEDIATELY after the
# pipe (`\|\s*(bash|sh)`). A single passthrough wrapper word inserted between the pipe and the shell —
# `| sudo bash`, `| env bash`, `| command bash`, `| nice bash` — slips the anchor entirely, and the
# classic bypass token `sudo` ESCALATES while it evades. Intentional — lets the pipe-to-shell
# wrapper-passthrough coverage-differential lane prove itself live by diffing the guard's verdict for
# the plain (no-wrapper) control against the wrapper-prefixed carrier on the pipe RHS.
_DANGER = re.compile(r"\|\s*(?:ba)?sh\b")


def is_dangerous_command(command):
    return _DANGER.search(command) is not None
