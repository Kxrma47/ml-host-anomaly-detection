from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any


REDACTED = "[REDACTED]"
_SENSITIVE_KEY = re.compile(
    r"(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|client[_-]?secret|"
    r"access[_-]?token|refresh[_-]?token|authorization|cookie|session[_-]?id)",
    re.IGNORECASE,
)
_SENSITIVE_OPTION = re.compile(
    r"^(?:--?|/)(?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|"
    r"access[_-]?token|refresh[_-]?token|authorization|cookie)$",
    re.IGNORECASE,
)
_KEY_VALUE = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|"
    r"access[_-]?token|refresh[_-]?token|authorization|cookie|session[_-]?id)"
    r"\b\s*[:=]\s*)([^\s,;]+|\"[^\"]*\"|'[^']*')"
)
_URL_CREDENTIAL = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^\s/:@]+:)([^\s@]+)(@)")
_AUTH_HEADER = re.compile(r"(?i)(\bauthorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+")


def is_sensitive_key(key: object) -> bool:
    return bool(_SENSITIVE_KEY.fullmatch(str(key).replace("-", "_")))


def redact_text(value: object) -> str:
    text = str(value)
    text = _URL_CREDENTIAL.sub(rf"\1{REDACTED}\3", text)
    text = _AUTH_HEADER.sub(rf"\1{REDACTED}", text)
    return _KEY_VALUE.sub(lambda match: f"{match.group(1)}{REDACTED}", text)


def redact_command_line(arguments: Sequence[object] | None) -> list[str]:
    if not arguments:
        return []

    redacted: list[str] = []
    hide_next = False
    for raw in arguments:
        value = str(raw)
        if hide_next:
            redacted.append(REDACTED)
            hide_next = False
            continue
        if _SENSITIVE_OPTION.fullmatch(value):
            redacted.append(value)
            hide_next = True
            continue
        redacted.append(redact_text(value))
    return redacted


def redact_data(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if is_sensitive_key(key) else redact_data(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, tuple):
        return [redact_data(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
