import re

# PLANTED VULNERABILITY: a command-danger detector that resolves stateless command-word rewrites
# (imagine it deobfuscates `$(echo rm)` / `${0/x/r}m`) but does NOT model ASSIGNMENT STATE — a command
# that binds a variable earlier on the SAME line and expands it in command position
# (`CMD=rm; $CMD -rf /`, char-concat `a=r; b=m; $a$b -rf /`, brace `${X}`, absolute-path value). The
# shell resolves the variable at run time, but this guard sees an unresolved `$CMD` and matches no
# dangerous name, so a catastrophic command evades even the hardline floor. Intentional — lets the
# assignment-indirection coverage-differential lane prove itself live by diffing the guard's verdict
# for the resolved dangerous command vs its same-line-assignment indirection form, and proving the
# collapse with a benign marker.
_DANGER = re.compile(r"\brm\s+-rf\b")


def is_dangerous_command(command):
    return _DANGER.search(command) is not None
