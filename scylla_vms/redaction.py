"""Small, deterministic redaction helpers for public diagnostics."""

import re
from collections.abc import Iterable

_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:PASSWORD|PRIVATE_KEY|SECRET|TOKEN)[A-Z0-9_]*)"
    r"(\s*=\s*)([^\s,;]+)"
)
_SENSITIVE_CLI_VALUE = re.compile(
    r"(?i)(--[a-z0-9-]*(?:password|private-key|secret|token)[a-z0-9-]*)"
    r"(?:\s+|=)([^\s,;]+)"
)


def redact(text: str, secrets: Iterable[str] = ()) -> str:
    """Remove supplied secret literals and obvious secret assignments."""

    redacted = text
    for secret in sorted((value for value in secrets if value), key=len, reverse=True):
        redacted = redacted.replace(secret, "[REDACTED]")
    redacted = _SENSITIVE_CLI_VALUE.sub(r"\1 [REDACTED]", redacted)
    return _SENSITIVE_ASSIGNMENT.sub(r"\1\2[REDACTED]", redacted)
