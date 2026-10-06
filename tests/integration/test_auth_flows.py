"""Phase 2 acceptance: authentication flows end to end through the HTTP API on PostgreSQL."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID

import asyncpg
import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from argus.core.config import Settings
from argus.core.ids import uuid7
from argus.infrastructure.db import Database
from argus.modules.audit.service import PLATFORM_CHAIN
from argus.security import totp
from tests.support import (
    STRONG_PASSWORD,
    ApiHarness,
    DatabaseURLs,
    api_harness,
    bearer,
    register_and_login,
    register_verified,
    token_from_email,
    unique_email,
)

pytestmark = pytest.mark.integration

AUTH = "/api/v1/auth"


@pytest.fixture
async def h(db_settings: Settings) -> AsyncIterator[ApiHarness]:
    async with api_harness(db_settings) as harness:
        yield harness


# --------------------------------------------------------------------------- registration
async def test_registration_verification_and_login(h: ApiHarness) -> None:
    email = unique_email()
    response = await h.client.post(
        f"{AUTH}/register",
        json={"email": email.upper(), "password": STRONG_PASSWORD, "full_name": "Ada"},
    )
    assert response.status_code == 202
    message = h.mailer.last_to(email)  # e-mail addresses are normalised to lower case
    assert "#token=argus_ot_" in message.text  # token travels in the URL fragment

    unverified = await h.client.post(
        f"{AUTH}/login", json={"email": email, "password": STRONG_PASSWORD}
    )
    assert unverified.status_code == 403

    token = token_from_email(message.text)
    assert (await h.client.post(f"{AUTH}/email/verify", json={"token": token})).status_code == 204
    again = await h.client.post(f"{AUTH}/email/verify", json={"token": token})
    assert again.status_code == 422  # single use

    login = await h.client.post(f"{AUTH}/login", json={"email": email, "password": STRONG_PASSWORD})
    assert login.status_code == 200
    body = login.json()
    assert body["status"] == "authenticated"
    assert body["token_type"] == "Bearer"
    assert body["refresh_token"].startswith("argus_rt_")
    me = await h.client.get(f"{AUTH}/me", headers=bearer(body["access_token"]))
    assert me.status_code == 200
    assert me.json()["email"] == email
    assert me.json()["email_verified"] is True


async def test_registration_does_not_reveal_existing_accounts(h: ApiHarness) -> None:
    email, _ = await register_and_login(h)
    response = await h.client.post(
        f"{AUTH}/register", json={"email": email, "password": STRONG_PASSWORD, "full_name": "Eve"}
    )
    assert response.status_code == 202
    fresh = await h.client.post(
        f"{AUTH}/register",
        json={"email": unique_email(), "password": STRONG_PASSWORD, "full_name": "New"},
    )
    assert response.json() == fresh.json()
    assert "already has an account" in h.mailer.last_to(email).text  # owner is informed instead


async def test_weak_password_is_rejected_with_reasons(h: ApiHarness) -> None:
    response = await h.client.post(
        f"{AUTH}/register",
        json={"email": unique_email(), "password": "password1234", "full_name": "Weak"},
    )
    assert response.status_code == 422
    assert "too common" in response.json()["detail"]
    assert "password1234" not in response.text


# ---------------------------------------------------------------------------------- login
async def test_unknown_email_and_wrong_password_are_indistinguishable(h: ApiHarness) -> None:
    email, _ = await register_and_login(h)
    wrong = await h.client.post(
        f"{AUTH}/login", json={"email": email, "password": "Wrong-password-123"}
    )
    unknown = await h.client.post(
        f"{AUTH}/login", json={"email": unique_email(), "password": "Wrong-password-123"}
    )
    assert wrong.status_code == unknown.status_code == 401

    def strip(r: httpx.Response) -> dict[str, object]:
        return {k: v for k, v in r.json().items() if k != "request_id"}

    assert strip(wrong) == strip(unknown)
    assert wrong.headers["www-authenticate"].startswith("Bearer")


async def test_repeated_failures_lock_known_and_unknown_accounts_alike(h: ApiHarness) -> None:
    email = await register_verified(h)
    unknown = unique_email()
    for target in (email, unknown):
        statuses = [
            (
                await h.client.post(
                    f"{AUTH}/login", json={"email": target, "password": "Wrong-password-123"}
                )
            ).status_code
            for _ in range(6)
        ]
        assert statuses == [401] * 5 + [429], (target, statuses)
    locked = await h.client.post(
        f"{AUTH}/login", json={"email": email, "password": STRONG_PASSWORD}
    )
    assert locked.status_code == 429
    assert int(locked.headers["retry-after"]) > 0


async def test_progressive_database_lockout_survives_limiter_reset(h: ApiHarness) -> None:
    email = await register_verified(h)
    for _ in range(5):
        await h.client.post(
            f"{AUTH}/login", json={"email": email, "password": "Wrong-password-123"}
        )
    await h.container.limiter.reset()  # type: ignore[attr-defined]  # e.g. Redis flushed
    response = await h.client.post(
        f"{AUTH}/login", json={"email": email, "password": STRONG_PASSWORD}
    )
    assert response.status_code == 429  # durable lock in PostgreSQL still applies
    h.clock.advance(61)
    ok = await h.client.post(f"{AUTH}/login", json={"email": email, "password": STRONG_PASSWORD})
    assert ok.status_code == 200


# ------------------------------------------------------------------------ token lifecycle
async def test_refresh_rotation_and_reuse_detection(h: ApiHarness) -> None:
    email, tokens = await register_and_login(h)
    first_refresh = tokens["refresh_token"]
    rotated = await h.client.post(f"{AUTH}/refresh", json={"refresh_token": first_refresh})
    assert rotated.status_code == 200
    new_tokens = rotated.json()
    assert new_tokens["refresh_token"] != first_refresh
    assert new_tokens["session_id"] == tokens["session_id"]

    replay = await h.client.post(f"{AUTH}/refresh", json={"refresh_token": first_refresh})
    assert replay.status_code == 401
    # the whole session is now dead: the latest tokens are rejected too
    assert (
        await h.client.post(f"{AUTH}/refresh", json={"refresh_token": new_tokens["refresh_token"]})
    ).status_code == 401
    assert (
        await h.client.get(f"{AUTH}/me", headers=bearer(new_tokens["access_token"]))
    ).status_code == 401
    assert "presented twice" in h.mailer.last_to(email).text


async def test_logout_takes_effect_immediately(h: ApiHarness) -> None:
    _, tokens = await register_and_login(h)
    headers = bearer(tokens["access_token"])
    assert (await h.client.post(f"{AUTH}/logout", headers=headers)).status_code == 204
    assert (await h.client.get(f"{AUTH}/me", headers=headers)).status_code == 401
    refresh = await h.client.post(
        f"{AUTH}/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert refresh.status_code == 401


async def test_sessions_can_be_listed_and_revoked_individually(h: ApiHarness) -> None:
    email, first = await register_and_login(h)
    second = (
        await h.client.post(f"{AUTH}/login", json={"email": email, "password": STRONG_PASSWORD})
    ).json()
    listing = await h.client.get(f"{AUTH}/sessions", headers=bearer(first["access_token"]))
    sessions = listing.json()
    assert len(sessions) == 2
    assert [s["current"] for s in sessions].count(True) == 1
    revoke = await h.client.delete(
        f"{AUTH}/sessions/{second['session_id']}", headers=bearer(first["access_token"])
    )
    assert revoke.status_code == 204
    assert (
        await h.client.get(f"{AUTH}/me", headers=bearer(second["access_token"]))
    ).status_code == 401
    assert (
        await h.client.get(f"{AUTH}/me", headers=bearer(first["access_token"]))
    ).status_code == 200


async def test_users_cannot_revoke_other_users_sessions(h: ApiHarness) -> None:
    _, alice = await register_and_login(h)
    _, bob = await register_and_login(h)
    response = await h.client.delete(
        f"{AUTH}/sessions/{bob['session_id']}", headers=bearer(alice["access_token"])
    )
    assert response.status_code == 404
    assert (
        await h.client.get(f"{AUTH}/me", headers=bearer(bob["access_token"]))
    ).status_code == 200


@pytest.mark.parametrize(
    "header",
    [None, "Basic dXNlcjpwYXNz", "Bearer", "Bearer not-a-jwt", "Bearer eyJhbGciOiJub25lIn0.e30."],
)
async def test_protected_endpoints_require_valid_bearer_tokens(
    h: ApiHarness, header: str | None
) -> None:
    headers = {"Authorization": header} if header else {}
    response = await h.client.get(f"{AUTH}/me", headers=headers)
    assert response.status_code == 401
    assert response.json()["code"] in {"authentication_required", "invalid_credentials"}


# ------------------------------------------------------------------------------ passwords
async def test_change_password_revokes_other_sessions(h: ApiHarness) -> None:
    email, first = await register_and_login(h)
    second = (
        await h.client.post(f"{AUTH}/login", json={"email": email, "password": STRONG_PASSWORD})
    ).json()
    wrong = await h.client.post(
        f"{AUTH}/password/change",
        json={"current_password": "Not-the-password-1", "new_password": "another-Strong-pass-77"},
        headers=bearer(first["access_token"]),
    )
    assert wrong.status_code == 401
    ok = await h.client.post(
        f"{AUTH}/password/change",
        json={"current_password": STRONG_PASSWORD, "new_password": "another-Strong-pass-77"},
        headers=bearer(first["access_token"]),
    )
    assert ok.status_code == 204
    assert (
        await h.client.get(f"{AUTH}/me", headers=bearer(first["access_token"]))
    ).status_code == 200
    assert (
        await h.client.get(f"{AUTH}/me", headers=bearer(second["access_token"]))
    ).status_code == 401


async def test_password_reset_flow(h: ApiHarness) -> None:
    email, tokens = await register_and_login(h)
    unknown = await h.client.post(f"{AUTH}/password/forgot", json={"email": unique_email()})
    known = await h.client.post(f"{AUTH}/password/forgot", json={"email": email})
    assert unknown.status_code == known.status_code == 202
    assert unknown.json() == known.json()
    token = token_from_email(h.mailer.last_to(email).text)

    new_password = "brand-New-secret-2026"
    reset = await h.client.post(
        f"{AUTH}/password/reset", json={"token": token, "new_password": new_password}
    )
    assert reset.status_code == 204
    assert (
        await h.client.get(f"{AUTH}/me", headers=bearer(tokens["access_token"]))
    ).status_code == 401
    reuse = await h.client.post(
        f"{AUTH}/password/reset", json={"token": token, "new_password": "yet-Another-pass-99"}
    )
    assert reuse.status_code == 422
    login = await h.client.post(f"{AUTH}/login", json={"email": email, "password": new_password})
    assert login.status_code == 200


async def test_password_reset_token_expires(h: ApiHarness) -> None:
    email, _ = await register_and_login(h)
    await h.client.post(f"{AUTH}/password/forgot", json={"email": email})
    token = token_from_email(h.mailer.last_to(email).text)
    h.clock.advance(31 * 60)
    response = await h.client.post(
        f"{AUTH}/password/reset", json={"token": token, "new_password": "brand-New-secret-2026"}
    )
    assert response.status_code == 422


# ------------------------------------------------------------------------------------ MFA
async def _enable_mfa(h: ApiHarness, access_token: str) -> tuple[str, list[str]]:
    enrol = await h.client.post(f"{AUTH}/mfa/totp/enroll", headers=bearer(access_token))
    assert enrol.status_code == 200
    secret = enrol.json()["secret"]
    assert enrol.json()["otpauth_uri"].startswith("otpauth://totp/")
    code = totp.code_at(secret, totp.current_step(h.clock.now()))
    confirm = await h.client.post(
        f"{AUTH}/mfa/totp/confirm", json={"code": code}, headers=bearer(access_token)
    )
    assert confirm.status_code == 200, confirm.text
    return secret, confirm.json()["recovery_codes"]


async def test_mfa_login_with_totp_replay_protection_and_recovery_codes(h: ApiHarness) -> None:
    email, tokens = await register_and_login(h)
    secret, recovery_codes = await _enable_mfa(h, tokens["access_token"])
    assert len(recovery_codes) == 10

    h.clock.advance(30)
    challenge = (
        await h.client.post(f"{AUTH}/login", json={"email": email, "password": STRONG_PASSWORD})
    ).json()
    assert challenge["status"] == "mfa_required"
    assert "access_token" not in challenge
    code = totp.code_at(secret, totp.current_step(h.clock.now()))
    verified = await h.client.post(
        f"{AUTH}/mfa/verify", json={"mfa_token": challenge["mfa_token"], "code": code}
    )
    assert verified.status_code == 200
    reuse_challenge = await h.client.post(
        f"{AUTH}/mfa/verify", json={"mfa_token": challenge["mfa_token"], "code": code}
    )
    assert reuse_challenge.status_code == 401  # challenge is single use

    second = (
        await h.client.post(f"{AUTH}/login", json={"email": email, "password": STRONG_PASSWORD})
    ).json()
    replay = await h.client.post(
        f"{AUTH}/mfa/verify", json={"mfa_token": second["mfa_token"], "code": code}
    )
    assert replay.status_code == 401  # same TOTP step cannot be used twice

    third = (
        await h.client.post(f"{AUTH}/login", json={"email": email, "password": STRONG_PASSWORD})
    ).json()
    by_recovery = await h.client.post(
        f"{AUTH}/mfa/verify", json={"mfa_token": third["mfa_token"], "code": recovery_codes[0]}
    )
    assert by_recovery.status_code == 200
    fourth = (
        await h.client.post(f"{AUTH}/login", json={"email": email, "password": STRONG_PASSWORD})
    ).json()
    reused_code = await h.client.post(
        f"{AUTH}/mfa/verify", json={"mfa_token": fourth["mfa_token"], "code": recovery_codes[0]}
    )
    assert reused_code.status_code == 401


async def test_mfa_challenge_dies_after_too_many_attempts(h: ApiHarness) -> None:
    email, tokens = await register_and_login(h)
    secret, _ = await _enable_mfa(h, tokens["access_token"])
    h.clock.advance(30)
    challenge = (
        await h.client.post(f"{AUTH}/login", json={"email": email, "password": STRONG_PASSWORD})
    ).json()
    for _ in range(5):
        bad = await h.client.post(
            f"{AUTH}/mfa/verify", json={"mfa_token": challenge["mfa_token"], "code": "000000"}
        )
        assert bad.status_code == 401
    good_code = totp.code_at(secret, totp.current_step(h.clock.now()))
    final = await h.client.post(
        f"{AUTH}/mfa/verify", json={"mfa_token": challenge["mfa_token"], "code": good_code}
    )
    assert final.status_code == 401  # the 6th attempt is refused even with the right code


async def test_disabling_mfa_requires_password_and_code(h: ApiHarness) -> None:
    _, tokens = await register_and_login(h)
    secret, _ = await _enable_mfa(h, tokens["access_token"])
    h.clock.advance(30)
    code = totp.code_at(secret, totp.current_step(h.clock.now()))
    wrong = await h.client.post(
        f"{AUTH}/mfa/disable",
        json={"password": "Wrong-password-123", "code": code},
        headers=bearer(tokens["access_token"]),
    )
    assert wrong.status_code == 401
    ok = await h.client.post(
        f"{AUTH}/mfa/disable",
        json={"password": STRONG_PASSWORD, "code": code},
        headers=bearer(tokens["access_token"]),
    )
    assert ok.status_code == 204
    me = await h.client.get(f"{AUTH}/me", headers=bearer(tokens["access_token"]))
    assert me.json()["mfa_enabled"] is False


# ---------------------------------------------------------------------------------- audit
async def test_audit_chain_is_valid_and_detects_tampering(
    h: ApiHarness, database_urls: DatabaseURLs, db_settings: Settings
) -> None:
    await register_and_login(h)
    await h.client.post(
        f"{AUTH}/login", json={"email": unique_email(), "password": "Wrong-password-123"}
    )
    owner_db = Database(
        db_settings.database.model_copy(update={"url": db_settings.database.migration_url})
    )
    try:
        async with owner_db.session() as session:
            result = await h.container.audit.verify_chain(session, PLATFORM_CHAIN)
            assert result.valid, result
            assert result.events >= 2
            actions = set(
                (
                    await session.execute(
                        text("SELECT action FROM audit_logs WHERE chain_key = 'platform'")
                    )
                ).scalars()
            )
            assert {"user.registered", "auth.login.succeeded", "auth.login.failed"} <= actions
            secrets_in_details = (
                await session.execute(
                    text("SELECT count(*) FROM audit_logs WHERE details::text ILIKE :pw"),
                    {"pw": f"%{STRONG_PASSWORD}%"},
                )
            ).scalar()
            assert secrets_in_details == 0
    finally:
        await owner_db.dispose()

    # An insider with superuser access edits a row: verification must notice.
    conn = await asyncpg.connect(database_urls.admin)
    try:
        await conn.execute("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_append_only")
        await conn.execute(
            "UPDATE audit_logs SET outcome = 'success' WHERE id = "
            "(SELECT max(id) FROM audit_logs WHERE action = 'auth.login.failed')"
        )
        await conn.execute("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_append_only")
    finally:
        await conn.close()
    owner_db = Database(
        db_settings.database.model_copy(update={"url": db_settings.database.migration_url})
    )
    try:
        async with owner_db.session() as session:
            tampered = await h.container.audit.verify_chain(session, PLATFORM_CHAIN)
    finally:
        await owner_db.dispose()
    assert not tampered.valid
    assert tampered.reason == "hash mismatch"
    # restore validity for later tests: re-apply the original value
    conn = await asyncpg.connect(database_urls.admin)
    try:
        await conn.execute("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_append_only")
        await conn.execute(
            "UPDATE audit_logs SET outcome = 'failure' WHERE id = "
            "(SELECT max(id) FROM audit_logs WHERE action = 'auth.login.failed')"
        )
        await conn.execute("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_append_only")
    finally:
        await conn.close()


async def test_runtime_role_cannot_modify_audit_records(
    h: ApiHarness, db_settings: Settings
) -> None:
    await register_and_login(h)
    db = Database(db_settings.database)
    try:
        with pytest.raises(DBAPIError, match="permission denied"):
            async with db.session() as session:
                await session.execute(text("DELETE FROM audit_logs"))
        with pytest.raises(DBAPIError, match="permission denied"):
            async with db.session() as session:
                await session.execute(text("UPDATE audit_logs SET action = 'x'"))
    finally:
        await db.dispose()


async def test_jwks_endpoint(h: ApiHarness) -> None:
    response = await h.client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert response.json()["keys"][0]["kid"] == "test-kid"
    assert "max-age" in response.headers["cache-control"]


async def test_expired_access_token_is_rejected(h: ApiHarness) -> None:
    _, tokens = await register_and_login(h)
    stale = h.container.tokens.issue_access_token(
        user_id=uuid7(),
        session_id=UUID(tokens["session_id"]),
        amr=("pwd",),
        now=datetime.now(UTC) - timedelta(hours=1),
    )
    assert (await h.client.get(f"{AUTH}/me", headers=bearer(stale.token))).status_code == 401
