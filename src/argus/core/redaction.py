"""Secret redaction for logs, audit details, error context and outgoing LLM prompts.

Two complementary detectors:

* **by key** - values stored under sensitive names (``password``, ``api_key``, ``authorization``,
  ``cookie``...) are replaced whatever they look like;
* **by shape** - credential-shaped substrings anywhere in free text (JWTs, our own ``argus_sk_``
  keys and ``argus_rt_`` tokens, provider keys, private-key blocks, DSN passwords, ``password=...``
  assignments, ``Bearer ...`` headers) are replaced inside otherwise harmless strings.

Redaction is intentionally conservative: a false positive costs a little log readability, a false
negative leaks a credential into every log sink and backup.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Final

REDACTED: Final = "[REDACTED]"
_MAX_DEPTH: Final = 12

_SAFE_KEYS: Final = frozenset(
    {
        "token_type",
        "tokens",
        "max_tokens",
        "token_count",
        "token_estimate",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "max_output_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
        "password_changed_at",
        "session_id",
        "key_id",
        "secret_ref",
    }
)
_SAFE_SUFFIXES: Final = ("_tokens", "_count", "_ttl_s", "_at", "_id", "_policy", "_required")

_SENSITIVE_KEY: Final = re.compile(
    r"pass(word|wd|phrase)?|secret|token|api_?key|apikey|authori[sz]ation|cookie|"
    r"private_?key|pepper|otp|totp|mfa_?code|recovery_?code|credential|signature|"
    r"access_?key|client_?secret|dsn|connection_?string|jwt|bearer",
    re.IGNORECASE,
)

# (name, pattern, replacement). Replacements keep the structure readable ("Bearer [REDACTED]").
_PATTERNS: Final[tuple[tuple[str, re.Pattern[str], str], ...]] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        REDACTED,
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        REDACTED,
    ),
    ("argus_api_key", re.compile(r"\bargus_sk_[a-z0-9]{12}_[A-Za-z0-9]{16,}"), REDACTED),
    ("argus_token", re.compile(r"\bargus_[a-z]{2}_[A-Za-z0-9_-]{16,}"), REDACTED),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}"), REDACTED),
    ("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"), REDACTED),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    (
        "github_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})"),
        REDACTED,
    ),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), REDACTED),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}"), REDACTED),
    ("stripe_key", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}"), REDACTED),
    (
        "auth_header",
        re.compile(r"(?i)\b(bearer|basic|token)(\s+)[A-Za-z0-9._~+/=-]{8,}"),
        rf"\1\2{REDACTED}",
    ),
    (
        "dsn_password",
        re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+:)([^\s@/]+)(@)"),
        rf"\1{REDACTED}\3",
    ),
    (
        "assignment",
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret|"
            r"refresh[_-]?token|access[_-]?token|auth[_-]?token)"
            r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
        ),
        rf"\1\2{REDACTED}",
    ),
)


def is_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    if normalized in _SAFE_KEYS or normalized.endswith(_SAFE_SUFFIXES):
        return False
    return bool(_SENSITIVE_KEY.search(normalized))


def redact_text(text: str) -> str:
    """Replace credential-shaped substrings in free text."""
    for _name, pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def contains_secret(text: str) -> bool:
    """True when :func:`redact_text` would change ``text`` (used by tests and prompt guards)."""
    return any(pattern.search(text) for _name, pattern, _ in _PATTERNS)


def redact(value: Any, *, _depth: int = 0) -> Any:
    """Return a redacted copy of ``value`` (mappings, sequences, strings; other types unchanged)."""
    if _depth > _MAX_DEPTH:
        return "[TRUNCATED]"
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and is_sensitive_key(key) and item not in (None, "", False):
                out[key] = REDACTED
            else:
                out[key] = redact(item, _depth=_depth + 1)
        return out
    if isinstance(value, list | tuple | set | frozenset):
        items = [redact(item, _depth=_depth + 1) for item in value]
        return items if isinstance(value, list | set | frozenset) else tuple(items)
    if isinstance(value, bytes | bytearray | memoryview):
        return f"[{len(value)} bytes]"
    return value
