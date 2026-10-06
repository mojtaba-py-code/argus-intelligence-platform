"""ids, crypto, pagination, retry and circuit breaker."""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime

import pytest

from argus.core.circuit_breaker import BreakerState, CircuitBreaker, CircuitOpenError
from argus.core.crypto import (
    CryptoError,
    Keyring,
    b64decode_secret,
    constant_time_equals,
    hmac_sha256,
)
from argus.core.errors import ValidationFailed
from argus.core.ids import base62, random_base62, secret_token, uuid7, uuid7_timestamp_ms
from argus.core.pagination import PageQuery, decode_cursor, encode_cursor
from argus.core.retry import RetryableError, RetryPolicy, retry_async


# ---------------------------------------------------------------------------------- ids
def test_uuid7_layout_and_time_ordering() -> None:
    before = time.time_ns() // 1_000_000
    first = uuid7()
    time.sleep(0.002)
    second = uuid7()
    assert first.version == 7
    assert first.variant == uuid.RFC_4122
    assert first < second
    assert abs(uuid7_timestamp_ms(first) - before) < 1000


def test_uuid7_values_are_unique() -> None:
    assert len({uuid7() for _ in range(5000)}) == 5000


def test_uuid7_is_strictly_increasing_within_a_millisecond() -> None:
    ids = [uuid7() for _ in range(5000)]  # many share a millisecond
    assert ids == sorted(ids)
    assert len({uuid7_timestamp_ms(i) for i in ids}) < len(ids)
    assert all(i.version == 7 and i.variant == uuid.RFC_4122 for i in ids)


def test_secret_tokens_have_prefix_and_entropy() -> None:
    token = secret_token("argus_rt")
    assert token.startswith("argus_rt_")
    assert len(token) >= len("argus_rt_") + 43
    assert secret_token("argus_rt") != token


def test_base62_alphabet() -> None:
    assert base62(b"\x00") == "0"
    assert set(random_base62(500)) <= set(
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    )


# ------------------------------------------------------------------------------- crypto
def _keyring(*ids: str, active: str) -> Keyring:
    return Keyring({key_id: key_id.encode().ljust(32, b"#") for key_id in ids}, active)


def test_keyring_round_trip_with_associated_data() -> None:
    ring = _keyring("k1", active="k1")
    blob = ring.encrypt(b"totp-secret", aad=b"user:1")
    assert ring.decrypt(blob, aad=b"user:1") == b"totp-secret"


def test_ciphertext_bound_to_its_context() -> None:
    ring = _keyring("k1", active="k1")
    blob = ring.encrypt(b"totp-secret", aad=b"user:1")
    with pytest.raises(CryptoError):
        ring.decrypt(blob, aad=b"user:2")


def test_tampering_is_detected() -> None:
    ring = _keyring("k1", active="k1")
    blob = bytearray(ring.encrypt(b"payload", aad=b""))
    blob[-1] ^= 0x01
    with pytest.raises(CryptoError):
        ring.decrypt(bytes(blob), aad=b"")


def test_rotation_keeps_old_ciphertexts_readable() -> None:
    old = _keyring("k1", active="k1")
    blob = old.encrypt(b"payload", aad=b"x")
    rotated = _keyring("k1", "k2", active="k2")
    assert rotated.decrypt(blob, aad=b"x") == b"payload"
    assert rotated.needs_rotation(blob)
    assert not rotated.needs_rotation(rotated.encrypt(b"payload", aad=b"x"))


def test_unknown_key_and_garbage_fail_closed() -> None:
    blob = _keyring("k1", active="k1").encrypt(b"p", aad=b"")
    with pytest.raises(CryptoError):
        _keyring("k9", active="k9").decrypt(blob, aad=b"")
    with pytest.raises(CryptoError):
        _keyring("k1", active="k1").decrypt(b"\x01", aad=b"")


def test_keyring_validation() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        Keyring({"k": b"short"}, "k")
    with pytest.raises(ValueError, match="active"):
        Keyring({"k": b"x" * 32}, "other")
    with pytest.raises(ValueError, match="base64"):
        b64decode_secret("not base64!!")


def test_hmac_parts_are_length_prefixed() -> None:
    key = b"k" * 32
    assert hmac_sha256(key, "ab", "c") != hmac_sha256(key, "a", "bc")
    assert constant_time_equals(hmac_sha256(key, "x"), hmac_sha256(key, "x"))


# --------------------------------------------------------------------------- pagination
def test_cursor_round_trip() -> None:
    ts = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
    ident = uuid7()
    cursor = decode_cursor(encode_cursor(ts, ident))
    assert cursor.created_at == ts
    assert cursor.id == ident


@pytest.mark.parametrize(
    "value",
    [
        "!!!",
        "e30",  # {}
        "x" * 300,
        "eyJ0IjoiOTk5OTktMDEtMDFUMDA6MDA6MDArMDA6MDAiLCJpIjoiMSJ9",  # year 99999
        "eyJ0IjoiMjAyNi0xMC0wNFQxMjowMDowMCIsImkiOiIwMTkyIn0",  # naive ts, bad uuid
    ],
)
def test_malformed_cursors_are_validation_errors(value: str) -> None:
    with pytest.raises(ValidationFailed):
        decode_cursor(value)


def test_page_query_bounds() -> None:
    with pytest.raises(ValueError, match="less than or equal"):
        PageQuery(limit=1000)


# ------------------------------------------------------------------------------- retry
async def test_retry_retries_only_retryable_errors() -> None:
    calls = 0
    delays: list[float] = []

    async def flaky() -> str:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise RetryableError("try again", retry_after_s=0.5)
        return "ok"

    async def fake_sleep(delay: float) -> None:
        delays.append(delay)

    result = await retry_async(
        flaky, policy=RetryPolicy(max_attempts=5, base_delay_s=0.01), sleep=fake_sleep
    )
    assert result == "ok"
    assert calls == 3
    assert all(delay >= 0.5 for delay in delays)  # Retry-After honoured


async def test_non_retryable_errors_propagate_immediately() -> None:
    calls = 0

    async def broken() -> None:
        nonlocal calls
        calls += 1
        raise ValueError("bad request")

    with pytest.raises(ValueError, match="bad request"):
        await retry_async(broken, policy=RetryPolicy(max_attempts=5))
    assert calls == 1


def test_backoff_is_bounded_full_jitter() -> None:
    policy = RetryPolicy(base_delay_s=1, max_delay_s=4)
    for attempt in range(1, 10):
        assert 0 <= policy.backoff(attempt) <= 4


# ----------------------------------------------------------------------- circuit breaker
def _state(breaker: CircuitBreaker) -> BreakerState:
    """A function call, so the type checker does not narrow the property between asserts."""
    return breaker.state


def test_breaker_opens_half_opens_and_closes() -> None:
    now = [0.0]
    breaker = CircuitBreaker("dep", failure_threshold=2, reset_timeout_s=10, clock=lambda: now[0])
    breaker.record_failure()
    assert _state(breaker) is BreakerState.CLOSED
    breaker.record_failure()
    assert _state(breaker) is BreakerState.OPEN
    with pytest.raises(CircuitOpenError):
        breaker.before_call()
    now[0] = 11
    assert _state(breaker) is BreakerState.HALF_OPEN
    breaker.before_call()  # the single trial call
    assert not breaker.allow()  # no second concurrent trial
    breaker.record_success()
    assert _state(breaker) is BreakerState.CLOSED


def test_failed_trial_reopens() -> None:
    now = [0.0]
    breaker = CircuitBreaker("dep", failure_threshold=1, reset_timeout_s=5, clock=lambda: now[0])
    breaker.record_failure()
    now[0] = 6
    breaker.before_call()
    breaker.record_failure()
    assert breaker.state is BreakerState.OPEN
