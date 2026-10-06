"""Identifiers and random tokens.

* :func:`uuid7` - RFC 9562 version-7 UUIDs: 48-bit millisecond timestamp, a 42-bit counter
  seeded randomly every millisecond (RFC 9562 section 6.2, method 1 - the layout CPython 3.14's
  ``uuid.uuid7`` uses) and 32 random bits. Ids from one process are strictly increasing, even
  within a millisecond, so ``ORDER BY created_at, id`` is a total, insertion-faithful order; the
  random bits keep ids infeasible to guess. Ids are identifiers, never secrets.
* :func:`secret_token` - prefixed, URL-safe secrets (refresh tokens, one-time tokens). The prefix
  lets log redaction and secret scanners recognise our credentials.
"""

from __future__ import annotations

import secrets
import string
import threading
import time
import uuid

_BASE62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
_TS_MASK = (1 << 48) - 1
_COUNTER_BITS = 42
_COUNTER_MAX = (1 << _COUNTER_BITS) - 1
_lock = threading.Lock()
_last_ms = 0
_last_counter = 0


def uuid7() -> uuid.UUID:
    """Return a new UUIDv7, strictly greater than every earlier one from this process."""
    global _last_ms, _last_counter
    with _lock:
        unix_ms = time.time_ns() // 1_000_000
        if unix_ms > _last_ms:
            counter = secrets.randbits(_COUNTER_BITS - 1)  # top bit clear: room to increment
        else:  # same millisecond, or the wall clock stepped back: keep counting
            unix_ms = _last_ms
            counter = _last_counter + 1
            if counter > _COUNTER_MAX:  # 2^41+ ids in one millisecond: borrow the next one
                unix_ms += 1
                counter = secrets.randbits(_COUNTER_BITS - 1)
        _last_ms, _last_counter = unix_ms, counter
    value = (
        ((unix_ms & _TS_MASK) << 80)
        | (0x7 << 76)  # version
        | ((counter >> 30) << 64)  # counter, high 12 bits
        | (0b10 << 62)  # RFC 4122/9562 variant
        | ((counter & ((1 << 30) - 1)) << 32)  # counter, low 30 bits
        | secrets.randbits(32)
    )
    return uuid.UUID(int=value)


def uuid7_timestamp_ms(value: uuid.UUID) -> int:
    """Milliseconds since the epoch encoded in a UUIDv7."""
    if value.version != 7:  # pragma: no cover - defensive
        msg = "not a UUIDv7"
        raise ValueError(msg)
    return value.int >> 80


def base62(data: bytes) -> str:
    """Encode bytes in base62 (no ``_``/``-`` so the result is safe inside ``_``-delimited keys)."""
    number = int.from_bytes(data, "big")
    if number == 0:
        return _BASE62[0]
    chars: list[str] = []
    while number:
        number, rem = divmod(number, 62)
        chars.append(_BASE62[rem])
    return "".join(reversed(chars))


def random_base62(length: int) -> str:
    """Uniformly random base62 string of exactly ``length`` characters."""
    return "".join(secrets.choice(_BASE62) for _ in range(length))


def random_lower_alnum(length: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def secret_token(prefix: str, nbytes: int = 32) -> str:
    """``<prefix>_<url-safe random>`` with at least ``nbytes`` of entropy (default 256 bits)."""
    if not prefix.isidentifier():  # pragma: no cover - programming error
        msg = "prefix must be an identifier"
        raise ValueError(msg)
    return f"{prefix}_{secrets.token_urlsafe(nbytes)}"
