import re

# PLANTED VULNERABILITY: a command-danger detector that surfaces the REAL command through passthrough
# wrappers before checking it — so `sudo sh -c '<danger>'` and `env sh -c '<danger>'` are still gated —
# but its wrapper list is INCOMPLETE. It threads {sudo, env, exec, nohup, setsid, time, command,
# builtin} yet not the equally-common resource/timing wrappers {timeout, nice, stdbuf, ionice, taskset,
# chrt, doas, runuser} nor the structural wrappers {find -exec, xargs -I{} sh -c}. Because the danger
# check is anchored to COMMAND POSITION (only fires when the danger is the resolved command, not merely
# present as a substring), an unthreaded wrapper leaves the inner command hidden and it evades.
# Intentional — lets the wrapper-passthrough-completeness coverage-differential lane prove itself live
# by diffing the guard's verdict for the bare command vs the same command behind an unthreaded wrapper.
_KNOWN_WRAPPER = re.compile(
    r"^\s*(?:sudo(?:\s+-\w+)*|env(?:\s+\w+=\S+)*|exec|nohup|setsid|time|command|builtin)\s+"
)
_SH_C = re.compile(r"^\s*(?:ba)?sh\s+-c\s+(['\"])(.*)\1\s*$")
# Anchored to command position: the danger must be the RESOLVED command, not a substring elsewhere.
_DANGER = re.compile(r"^\s*(?:curl\b.*\|\s*(?:ba)?sh\b|rm\s+-rf\b)")


def is_dangerous_command(command):
    c = command
    for _ in range(6):
        stripped = _KNOWN_WRAPPER.sub("", c)
        m = _SH_C.match(stripped)
        if m:
            stripped = m.group(2)
        if stripped == c:
            break
        c = stripped
    return _DANGER.search(c) is not None
