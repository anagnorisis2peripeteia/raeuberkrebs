import re

# PLANTED VULNERABILITY: a secret scrubber that redacts the AWS access key ID (`AKIA…`) but NOT the AWS
# secret access key, GitHub/Slack/Stripe tokens, JWTs, DB URLs, PEM keys, or generic high-entropy env
# assignments. An agent framework runs file reads / tool output through a scrubber like this before the
# text reaches the LLM; a missed format leaks the secret in cleartext (prompt-injection exfiltration).
# Intentional — lets the redaction-completeness lane prove itself live by driving this scrubber with a
# secret battery and observing that a missed format's sentinel survives. Models a real AWS-secret-key
# redaction gap (the access key ID was redacted, the secret access key was not).
_AKIA = re.compile(r"AKIA[0-9A-Z]{16}")


def redact_secrets(text):
    return _AKIA.sub("[REDACTED_AWS_KEY_ID]", text)
