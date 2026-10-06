"""Phase 2 primitives: passwords, tokens, TOTP, rate limiting, permissions, key loading."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import fakeredis
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from argus.core.config import ConfigurationError, Environment
from argus.core.errors import InvalidCredentials, ValidationFailed
from argus.core.ids import uuid7
from argus.infrastructure.redis import RedisKeys
from argus.security import totp
from argus.security.keys import JWTKeys, load_key_material
from argus.security.passwords import fast_test_hasher, password_problems, validate_password
from argus.security.permissions import (
    API_KEY_SCOPES,
    ORG_ROLE_PERMISSIONS,
    PROJECT_ROLE_PERMISSIONS,
    OrgRole,
    Permission,
    ProjectRole,
)
from argus.security.ratelimit import MemoryRateLimiter, RatePolicy, RedisRateLimiter
from argus.security.tokens import TokenService
from tests.support import make_settings

pytestmark = pytest.mark.security


# ------------------------------------------------------------------------------ passwords
@pytest.mark.parametrize(
    ("password", "reason"),
    [
        ("short-pass", "at least 12"),
        ("x" * 129, "at most 128"),
        ("password1234", "too common"),
        ("Password2026!", "too common"),
        ("qwertyuiop123", "too common"),
        ("aaaaaaaaaaaaaaaa", "pattern"),
        ("abcabcabcabcabc", "pattern"),
        ("123456789012345", "pattern"),
        ("asdfghjkl", "at least 12"),
        ("mojtaba-is-secure-42", "e-mail"),
    ],
)
def test_password_policy_rejections(password: str, reason: str) -> None:
    problems = password_problems(password, email="mojtaba@example.com")
    assert any(reason in problem for problem in problems), problems


@pytest.mark.parametrize(
    "password", ["correct-Horse-battery-42", "Ünïcödé pass phrase 99", "a perfectly fine sentence"]
)
def test_password_policy_accepts_good_passphrases(password: str) -> None:
    assert password_problems(password, email="someone@example.com") == []


def test_validate_password_raises_without_echoing_the_password() -> None:
    with pytest.raises(ValidationFailed) as caught:
        validate_password("password1234")
    assert "password1234" not in str(caught.value.detail)


def test_hasher_round_trip_rehash_and_unicode_normalisation() -> None:
    hasher = fast_test_hasher()
    hashed = hasher.hash("Café pass phrase 1")
    assert hashed.startswith("$argon2id$")
    assert hasher.verify(hashed, "Café pass phrase 1")
    assert hasher.verify(hashed, "Café pass phrase 1")  # same text, decomposed form
    assert not hasher.verify(hashed, "wrong")
    assert not hasher.verify("not-a-hash", "x")
    stronger = type(hasher)(time_cost=2, memory_cost_kib=2048, parallelism=1)
    assert stronger.needs_rehash(hashed)


# --------------------------------------------------------------------------------- tokens
def _token_service(kid: str = "k1", key: Ed25519PrivateKey | None = None) -> TokenService:
    key = key or Ed25519PrivateKey.generate()
    return TokenService(JWTKeys(kid, {kid: key}), issuer="argus", audience="argus-api", ttl_s=600)


def test_access_token_round_trip() -> None:
    service = _token_service()
    user, sid = uuid7(), uuid7()
    issued = service.issue_access_token(
        user_id=user, session_id=sid, amr=("pwd",), now=datetime.now(UTC)
    )
    claims = service.verify_access_token(issued.token)
    assert claims.user_id == user
    assert claims.session_id == sid
    assert claims.amr == ("pwd",)


def test_expired_token_is_rejected() -> None:
    service = _token_service()
    issued = service.issue_access_token(
        user_id=uuid7(), session_id=uuid7(), amr=(), now=datetime.now(UTC) - timedelta(hours=2)
    )
    with pytest.raises(InvalidCredentials):
        service.verify_access_token(issued.token)


def test_token_signed_by_another_key_is_rejected() -> None:
    attacker = _token_service("k1")  # same kid, different key
    victim = _token_service("k1")
    issued = attacker.issue_access_token(
        user_id=uuid7(), session_id=uuid7(), amr=(), now=datetime.now(UTC)
    )
    with pytest.raises(InvalidCredentials):
        victim.verify_access_token(issued.token)


def _claims(now: datetime) -> dict[str, object]:
    return {
        "iss": "argus",
        "aud": "argus-api",
        "sub": str(uuid7()),
        "sid": str(uuid7()),
        "jti": "x",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }


def test_alg_none_and_hs256_confusion_are_rejected() -> None:
    key = Ed25519PrivateKey.generate()
    service = _token_service("k1", key)
    now = datetime.now(UTC)
    unsigned = jwt.encode(
        _claims(now),
        None,  # type: ignore[arg-type]  # "none" needs no key; the type stubs disagree
        algorithm="none",
        headers={"kid": "k1", "typ": "at+jwt"},
    )
    with pytest.raises(InvalidCredentials):
        service.verify_access_token(unsigned)
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Classic confusion: HMAC-"sign" with the *public* key as the secret. PyJWT refuses to
    # produce such a token, so it is assembled by hand exactly as an attacker would.
    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    header = b64(json.dumps({"alg": "HS256", "kid": "k1", "typ": "at+jwt"}).encode())
    payload = b64(json.dumps(_claims(now)).encode())
    signature = b64(hmac.new(public_pem, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    with pytest.raises(InvalidCredentials):
        service.verify_access_token(f"{header}.{payload}.{signature}")


@pytest.mark.parametrize(
    "mutation",
    [
        {"aud": "someone-else"},
        {"iss": "evil"},
        {"sid": None},
        {"exp": None},
    ],
)
def test_claim_validation(mutation: dict[str, object]) -> None:
    key = Ed25519PrivateKey.generate()
    service = _token_service("k1", key)
    claims = _claims(datetime.now(UTC))
    for name, value in mutation.items():
        if value is None:
            claims.pop(name)
        else:
            claims[name] = value
    token = jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": "k1", "typ": "at+jwt"})
    with pytest.raises(InvalidCredentials):
        service.verify_access_token(token)


def test_wrong_typ_or_unknown_kid_is_rejected() -> None:
    key = Ed25519PrivateKey.generate()
    service = _token_service("k1", key)
    claims = _claims(datetime.now(UTC))
    other_typ = jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": "k1", "typ": "JWT"})
    unknown_kid = jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": "k2", "typ": "at+jwt"})
    for token in (other_typ, unknown_kid, "garbage", "a.b.c", "x" * 5000):
        with pytest.raises(InvalidCredentials):
            service.verify_access_token(token)


def test_jwks_publishes_only_public_material() -> None:
    key = Ed25519PrivateKey.generate()
    jwks = _token_service("k1", key).jwks()
    (entry,) = jwks["keys"]
    assert entry["kty"] == "OKP"
    assert entry["crv"] == "Ed25519"
    assert entry["kid"] == "k1"
    raw = base64.urlsafe_b64decode(entry["x"] + "=")
    assert raw == key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert "d" not in entry


# ----------------------------------------------------------------------------------- TOTP
def test_totp_accepts_drift_and_rejects_replay() -> None:
    secret = totp.new_secret()
    now = datetime(2026, 10, 4, 12, 0, 15, tzinfo=UTC)
    step = totp.current_step(now)
    code = totp.code_at(secret, step)
    assert totp.verify_code(secret, code, now=now, last_used_step=None) == step
    assert totp.verify_code(secret, code, now=now, last_used_step=step) is None  # replay
    previous = totp.code_at(secret, step - 1)
    assert totp.verify_code(secret, previous, now=now, last_used_step=None) == step - 1
    far = totp.code_at(secret, step - 5)
    assert totp.verify_code(secret, far, now=now, last_used_step=None) is None


@pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", "12 34 5x"])
def test_totp_rejects_malformed_codes(code: str) -> None:
    assert (
        totp.verify_code(totp.new_secret(), code, now=datetime.now(UTC), last_used_step=None)
        is None
    )


def test_recovery_codes_are_unique_unambiguous_and_hashed_with_pepper() -> None:
    codes = totp.new_recovery_codes()
    assert len(set(codes)) == 10
    for code in codes:
        assert totp.looks_like_recovery_code(code)
        assert not set(code.replace("-", "")) & set("01ilo")
    assert totp.hash_recovery_code(b"p" * 32, codes[0]) == totp.hash_recovery_code(
        b"p" * 32, codes[0].upper()
    )
    assert totp.hash_recovery_code(b"p" * 32, codes[0]) != totp.hash_recovery_code(
        b"q" * 32, codes[0]
    )


# ---------------------------------------------------------------------------- rate limits
async def test_memory_gcra_allows_burst_then_spaces_requests() -> None:
    now = [0.0]
    limiter = MemoryRateLimiter(clock=lambda: now[0])
    policy = RatePolicy("t", limit=5, period_s=50, burst=5)  # one per 10 s after a burst of 5
    results = [await limiter.hit(policy, "k") for _ in range(6)]
    assert [r.allowed for r in results] == [True] * 5 + [False]
    assert results[0].remaining == 4
    assert 9.9 < results[5].retry_after_s <= 10.0
    now[0] = 10.0
    assert (await limiter.hit(policy, "k")).allowed
    assert not (await limiter.hit(policy, "k")).allowed
    assert (await limiter.hit(policy, "other-key")).allowed  # keys are independent


async def test_memory_limiter_is_bounded() -> None:
    limiter = MemoryRateLimiter(max_keys=10)
    policy = RatePolicy("t", limit=1, period_s=60)
    for i in range(100):
        await limiter.hit(policy, f"k{i}")
    assert len(limiter._tat) == 10


async def test_redis_gcra_script_matches_memory_semantics() -> None:
    redis = fakeredis.FakeAsyncRedis()
    limiter = RedisRateLimiter(redis, RedisKeys("argus", Environment.TESTING))
    policy = RatePolicy("t", limit=3, period_s=60, burst=3)
    results = [await limiter.hit(policy, "client-1") for _ in range(4)]
    assert [r.allowed for r in results] == [True, True, True, False]
    assert results[3].retry_after_s > 0
    assert not any(r.degraded for r in results)
    keys = [k.decode() if isinstance(k, bytes) else str(k) for k in await redis.keys("*")]
    assert keys
    assert all("client-1" not in k for k in keys)  # keys are digests, not raw identifiers


class _BrokenRedis(fakeredis.FakeAsyncRedis):
    async def evalsha(self, *args: object, **kwargs: object) -> object:
        raise ConnectionError("redis down")

    async def eval(self, *args: object, **kwargs: object) -> object:
        raise ConnectionError("redis down")


async def test_redis_outage_degrades_to_local_limits_not_to_no_limits() -> None:
    limiter = RedisRateLimiter(_BrokenRedis(), RedisKeys("argus", Environment.TESTING))
    policy = RatePolicy("t", limit=2, period_s=60, burst=2)
    results = [await limiter.hit(policy, "k") for _ in range(3)]
    assert [r.allowed for r in results] == [True, True, False]
    assert all(r.degraded for r in results)


# ---------------------------------------------------------------------------- permissions
def test_role_matrix_is_monotonic() -> None:
    viewer = ORG_ROLE_PERMISSIONS[OrgRole.VIEWER]
    analyst = ORG_ROLE_PERMISSIONS[OrgRole.ANALYST]
    admin = ORG_ROLE_PERMISSIONS[OrgRole.ADMIN]
    owner = ORG_ROLE_PERMISSIONS[OrgRole.OWNER]
    assert viewer < analyst < admin < owner
    assert owner == frozenset(Permission)
    assert Permission.ORG_DELETE not in admin
    assert all(p.value.endswith((":read", ":read_restricted")) for p in viewer)


def test_project_roles_never_exceed_analyst() -> None:
    analyst = ORG_ROLE_PERMISSIONS[OrgRole.ANALYST]
    for role in ProjectRole:
        assert PROJECT_ROLE_PERMISSIONS[role] <= analyst


def test_api_keys_can_never_carry_account_takeover_scopes() -> None:
    for dangerous in (
        Permission.APIKEYS_MANAGE,
        Permission.MEMBERS_MANAGE,
        Permission.ORG_DELETE,
        Permission.SECURITY_MANAGE,
    ):
        assert dangerous not in API_KEY_SCOPES


# --------------------------------------------------------------------------- key material
def test_key_material_loads_from_settings() -> None:
    keys = load_key_material(make_settings())
    assert keys.jwt.active_kid == "test-kid"
    assert len(keys.api_key_pepper) == 32
    assert not keys.ephemeral


def test_incomplete_keys_fail_outside_development() -> None:
    with pytest.raises(ConfigurationError, match="incomplete"):
        load_key_material(make_settings(auth={"api_key_pepper": None}))


def test_development_generates_ephemeral_keys() -> None:
    keys = load_key_material(
        make_settings(environment="development", auth={"jwt_signing_keys": None})
    )
    assert keys.ephemeral


def test_non_ed25519_jwt_keys_are_rejected() -> None:
    from cryptography.hazmat.primitives.asymmetric import ec

    pem = (
        ec.generate_private_key(ec.SECP256R1())
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    with pytest.raises(ConfigurationError, match="Ed25519"):
        load_key_material(make_settings(auth={"jwt_signing_keys": json.dumps({"test-kid": pem})}))
