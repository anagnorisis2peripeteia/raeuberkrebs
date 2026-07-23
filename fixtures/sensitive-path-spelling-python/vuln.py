import re

# PLANTED VULNERABILITY: a command-danger detector that denylists sensitive-file writes (SSH keys,
# shell-rc, netrc via redirect/tee/cp/sed) but anchors the home directory as `~` / `$HOME` ONLY. The
# SAME logical file reached by a different spelling — an absolute `/home/<u>/.ssh/…`, `/Users/<u>/…`
# (macOS), `/root/…`, or a relative `.ssh/…` from the home cwd — all evade, so an SSH-key / shell-rc
# backdoor installs with no prompt. Separately, whole PERSISTENCE carriers (`crontab -` install from
# stdin/file, setuid `chmod +s`) are simply absent from the denylist. Intentional — lets the
# sensitive-path spelling-equivalence coverage-differential lane prove itself live by diffing the
# guard's verdict for the `~`-anchored control vs an equivalent-spelling / uncovered-persistence carrier.
_SENSITIVE = re.compile(
    r"(?:>>|>|\btee\b|\bcp\b|\bsed\b).*(?:~|\$HOME|\$\{HOME\})/\.(?:ssh|bashrc|bash_profile|profile|zshrc|netrc)"
)


def is_dangerous_command(command):
    return _SENSITIVE.search(command) is not None
