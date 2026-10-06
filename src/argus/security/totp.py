"""TOTP (RFC 6238) and recovery codes.

* Codes are checked for the current 30-second step and one step either side (clock drift), and a
  code is accepted only if its step is **later** than the last step used - so an observed code
  cannot be replayed within its validity window.
* Comparison is constant-time.
* Recovery codes are random (60 bits each, unambiguous alphabet), shown once, and stored only as
  HMAC-SHA-256 under the server-side pepper: high-entropy single-use secrets need no slow hash,
  and the pepper makes an offline guess impossible without the server's key.
"""

from __future__ import annotations

import hmac
import re
import secrets
from datetime import datetime
from typing import Final

import pyotp

from argus.core.crypto import hmac_sha256

STEP_SECONDS: Final = 30
DIGITS: Final = 6
_CODE: Final = re.compile(r"^\d{6}$")
_RECOVERY_ALPHABET: Final = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o, 1/l/i
RECOVERY_CODE_COUNT: Final = 10


def new_secret() -> str:
    return pyotp.random_base32(length=32)


def provisioning_uri(secret: str, *, account: str, issuer: str = "Argus") -> str:
    return str(
        pyotp.TOTP(secret, digits=DIGITS, interval=STEP_SECONDS).provisioning_uri(
            name=account, issuer_name=issuer
        )
    )


def current_step(now: datetime) -> int:
    return int(now.timestamp()) // STEP_SECONDS


def code_at(secret: str, step: int) -> str:
    return str(pyotp.TOTP(secret, digits=DIGITS, interval=STEP_SECONDS).generate_otp(step))


def verify_code(
    secret: str, code: str, *, now: datetime, last_used_step: int | None, window: int = 1
) -> int | None:
    """Return the matched step (to store as ``last_used_step``) or ``None``."""
    code = code.strip().replace(" ", "")
    if not _CODE.fullmatch(code):
        return None
    matched: int | None = None
    now_step = current_step(now)
    for step in range(now_step - window, now_step + window + 1):
        expected = code_at(secret, step)
        # evaluate every candidate (no early exit) to keep timing independent of the match
        if hmac.compare_digest(expected, code) and (
            last_used_step is None or step > last_used_step
        ):
            matched = step
    return matched


def new_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(12))
        codes.append(f"{raw[:4]}-{raw[4:8]}-{raw[8:]}")
    return codes


def normalise_recovery_code(code: str) -> str:
    return re.sub(r"[\s-]", "", code.strip().lower())


def looks_like_recovery_code(code: str) -> bool:
    normalised = normalise_recovery_code(code)
    return len(normalised) == 12 and all(ch in _RECOVERY_ALPHABET for ch in normalised)


def hash_recovery_code(pepper: bytes, code: str) -> bytes:
    return hmac_sha256(pepper, "recovery-code", normalise_recovery_code(code))
