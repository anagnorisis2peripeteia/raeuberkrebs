import re

# PLANTED VULNERABILITY: a command-danger detector that gates decode-and-execute when the executor is a
# PIPED SHELL (`… | base64 -d | bash`, Class 3) and gates remote content via command-substitution under
# eval (`eval $(curl …)`, Class 2), but leaves the SAME primitives uncovered when the executor is
# `eval`/`source`/`.` of a substitution that itself contains a DECODER, and when the substitution is a
# PROCESS-substitution `<(…)`. The reconstructed command carries no dangerous keyword in its literal
# text, so it runs with no approval prompt. Intentional — lets the decode-and-execute
# coverage-differential lane prove itself live by diffing the guard's verdict for a gated Class-2/3
# control vs an evading eval/source/process-substitution carrier.
_CLASS3 = re.compile(
    r"(?:base64\s+-d|base64\s+--decode|base32\s+-d|xxd\s+-r|openssl\s+(?:base64|enc)\s+-d|curl|wget)\s*\|\s*(?:ba|z|k)?sh\b"
)
_CLASS2 = re.compile(r"\beval\b.*(?:\$\(|`)\s*(?:curl|wget)\b")


def detect_dangerous_command(command):
    return _CLASS2.search(command) is not None or _CLASS3.search(command) is not None
