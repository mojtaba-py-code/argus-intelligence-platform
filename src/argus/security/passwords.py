"""Password hashing (Argon2id) and password policy (NIST SP 800-63B style).

Policy: length 12-128, no composition rules, rejected when the password is a known-common
password, a trivial pattern (repetition, sequences, keyboard walks, "password2026!"), or contains
the account's e-mail local part. The 128-character cap bounds hashing work per request.

Hashing: Argon2id with the RFC 9106 *low-memory* recommended parameters (t=3, m=64 MiB, p=4),
transparently upgraded at login when the parameters change (:meth:`PasswordHasher.needs_rehash`).
Unknown accounts still pay for one verification (:meth:`dummy_verify`) so response timing does
not reveal whether an e-mail address is registered.
"""

from __future__ import annotations

import itertools
import re
import unicodedata
from dataclasses import dataclass, field
from functools import cached_property
from typing import Final

from argon2 import PasswordHasher as _Argon2
from argon2 import Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from argus.core.errors import ValidationFailed

MIN_LENGTH: Final = 12
MAX_LENGTH: Final = 128

# Long passwords that still appear at the top of breach corpora (lower-case comparison).
COMMON_PASSWORDS: Final = frozenset(
    {
        "123456789012",
        "1234567890123",
        "12345678901234",
        "123456789123",
        "111111111111",
        "000000000000",
        "123123123123",
        "121212121212",
        "abcdefghijkl",
        "abc123abc123",
        "qwertyuiopas",
        "qwertyuiop12",
        "qwertyuiop123",
        "qwerty123456",
        "qwerty12345678",
        "1q2w3e4r5t6y",
        "1q2w3e4r5t6y7u",
        "1qaz2wsx3edc",
        "zaq12wsxcde3",
        "zaq1zaq1zaq1",
        "asdfghjkl123",
        "asdfghjklqwe",
        "zxcvbnm12345",
        "passwordpassword",
        "password1234",
        "password12345",
        "password123456",
        "password123!",
        "password2024",
        "password2025",
        "password2026",
        "p@ssw0rd1234",
        "passw0rd1234",
        "iloveyou1234",
        "iloveyouiloveyou",
        "letmeinletmein",
        "letmein12345",
        "welcome12345",
        "welcome123456",
        "welcomewelcome",
        "administrator",
        "administrator1",
        "changeme1234",
        "changemenow!",
        "trustno1trustno1",
        "football1234",
        "baseball1234",
        "superman1234",
        "starwars1234",
        "princess1234",
        "sunshine1234",
        "monkey123456",
        "dragon123456",
        "master123456",
        "shadow123456",
        "michael12345",
        "jennifer1234",
        "computer1234",
        "internet1234",
        "secret123456",
        "whatever1234",
        "freedom12345",
        "liverpool123",
        "chelsea12345",
        "arsenal12345",
        "manchester12",
        "barcelona123",
        "realmadrid12",
        "pokemon12345",
        "minecraft123",
        "q1w2e3r4t5y6",
        "a1b2c3d4e5f6",
        "1a2b3c4d5e6f",
        "987654321098",
        "098765432109",
        "11223344556677",
        "112233445566",
        "aaaaaaaaaaaa",
        "qqqqqqqqqqqq",
        "zzzzzzzzzzzz",
        "correcthorsebatterystaple",
        "thequickbrownfox",
        "loveyouforever",
        "mypassword123",
        "mysecretpassword",
        "letmein123456",
        "access123456",
        "default12345",
        "guest1234567",
        "root12345678",
        "toor12345678",
        "adminadmin123",
        "admin123456789",
        "admin@123456",
    }
)
_KEYBOARD_ROWS: Final = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "1qaz2wsx3edc4rfv")
_BASE_WORDS: Final = re.compile(
    r"^(password|passw0rd|p@ssw0rd|qwerty|letmein|welcome|admin|administrator|argus|changeme|"
    r"iloveyou|monkey|dragon|secret|login|master|default)[\W\d_]*$"
)


def _normalise(password: str) -> str:
    return unicodedata.normalize("NFKC", password)


def _is_repetition(value: str) -> bool:
    """True for 'aaaa...', 'abcabcabc...' (a short block repeated)."""
    for period in range(1, 5):
        if (
            len(value) >= period * 3
            and value == (value[:period] * (len(value) // period + 1))[: len(value)]
        ):
            return True
    return False


def _is_sequence(value: str) -> bool:
    """'abcdef...', '987654...' and digit runs that wrap ('1234567890123')."""
    if len(value) < 6:
        return False
    if value.isdigit():
        steps = {(int(b) - int(a)) % 10 for a, b in itertools.pairwise(value)}
        return steps in ({1}, {9})
    deltas = {ord(b) - ord(a) for a, b in itertools.pairwise(value)}
    return deltas in ({1}, {-1})


def _is_keyboard_walk(value: str) -> bool:
    return any(value in row or value in row[::-1] for row in _KEYBOARD_ROWS if len(value) >= 6)


def password_problems(password: str, *, email: str | None = None) -> list[str]:
    """Human-readable reasons a password is unacceptable (empty list = acceptable)."""
    password = _normalise(password)
    problems: list[str] = []
    if len(password) < MIN_LENGTH:
        problems.append(f"must be at least {MIN_LENGTH} characters long")
    if len(password) > MAX_LENGTH:
        problems.append(f"must be at most {MAX_LENGTH} characters long")
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS or _BASE_WORDS.match(lowered):
        problems.append("is too common")
    elif _is_repetition(lowered) or _is_sequence(lowered) or _is_keyboard_walk(lowered):
        problems.append("is a predictable pattern")
    if email:
        local = email.split("@", 1)[0].lower()
        if len(local) >= 4 and local in lowered:
            problems.append("must not contain your e-mail address")
    return problems


def validate_password(password: str, *, email: str | None = None) -> None:
    problems = password_problems(password, email=email)
    if problems:
        raise ValidationFailed(
            "The password " + "; ".join(problems) + ".",
            extensions={
                "errors": [
                    {"loc": ["body", "password"], "msg": p, "type": "password_policy"}
                    for p in problems
                ]
            },
        )


@dataclass
class PasswordHasher:
    time_cost: int = 3
    memory_cost_kib: int = 64 * 1024
    parallelism: int = 4
    _impl: _Argon2 = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._impl = _Argon2(
            time_cost=self.time_cost,
            memory_cost=self.memory_cost_kib,
            parallelism=self.parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )

    def hash(self, password: str) -> str:
        return self._impl.hash(_normalise(password))

    def verify(self, password_hash: str, password: str) -> bool:
        try:
            return self._impl.verify(password_hash, _normalise(password))
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, password_hash: str) -> bool:
        try:
            return self._impl.check_needs_rehash(password_hash)
        except InvalidHashError:
            return True

    @cached_property
    def _dummy_hash(self) -> str:
        return self.hash("argus-dummy-password-for-timing-equalisation")

    def dummy_verify(self, password: str) -> None:
        """Spend the same work as a real verification (unknown account)."""
        self.verify(self._dummy_hash, password)


def fast_test_hasher() -> PasswordHasher:
    """Cheap parameters for the test-suite only - injected explicitly, never configurable."""
    return PasswordHasher(time_cost=1, memory_cost_kib=1024, parallelism=1)
