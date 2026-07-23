import re

# PLANTED VULNERABILITY: a scrubber with a `code_file` context flag. To avoid false positives on SOURCE
# CODE (`API_KEY = os.getenv("X")`, `MAX_TOKENS=8000`), file/code reads set `code_file=True`, which SKIPS
# the ENV / JSON / YAML assignment passes entirely. But those same passes are what redact real config
# secrets — so a `.env`/`.ini`/`.yaml`/`.json` CONFIG file read back through the file-content path
# (also `code_file=True`) leaks `DB_PASSWORD=…`, `password: …`, `{"password": …}` in cleartext, while
# the identical string in default mode is redacted. Intentional — lets the redaction mode-differential
# lane prove itself live by driving the SAME secret across modes and observing the disagreement.
_ASSIGN = re.compile(
    r"(?i)\b(password|passwd|secret|db_password|api[_-]?key|access[_-]?key)\b\s*[:=]\s*[\"']?([^\s\"',}]+)"
)


def redact_sensitive_text(text, code_file=False):
    if code_file:
        # skip the assignment passes on "source code" -> LEAKS config secrets read via the file path
        return text
    return _ASSIGN.sub(lambda m: m.group(0).replace(m.group(2), "[REDACTED]"), text)
