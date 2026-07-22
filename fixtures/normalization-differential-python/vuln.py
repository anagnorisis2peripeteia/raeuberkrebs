import re

# PLANTED VULNERABILITY: a command-danger detector that matches the raw command string but never
# decodes bash ANSI-C quoting ($'\xNN') or expands brace lists ({a,b,c}). Because the command is later
# run through a shell, an obfuscated form that bash collapses back to `rm -rf /` (etc.) evades this
# guard even though it executes the destructive command. Intentional — exists so the Raeuberkrebs
# normalization-differential lane can prove itself live by diffing this detector against the shell.
_DANGER = re.compile(r"\brm\s+-rf|\bmkfs\b|\bchmod\s+-R\s+777|\bshutdown\b|\bdd\b.*\bof=/dev/")


def is_dangerous_command(command):
    return _DANGER.search(command) is not None
