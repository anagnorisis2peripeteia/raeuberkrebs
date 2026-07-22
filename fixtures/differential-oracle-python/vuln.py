# PLANTED VULNERABILITY (command-approval divergence): a command-safety control that only rejects a
# small hardcoded blacklist of destructive binaries. It therefore APPROVES commands that carry shell
# metacharacters (`;`, `$(...)`, backticks, `|`, `&&`) as long as they don't mention a blacklisted
# name — so an injected command still runs. Intentional — exists so the Raeuberkrebs differential-
# oracle Python lane can prove itself live by diffing this gate's belief against ground truth.
_BLOCKED = ("rm", "dd", "mkfs", "shutdown", "reboot")


def is_command_safe(cmd):
    return not any(bad in cmd for bad in _BLOCKED)
