"""Phase 23 acceptance: the operator's incident-response tools.

* disabling an account stops everything it can do *now* - open sessions, new sign-ins and the
  API keys it owns - and enabling it never revives an old session;
* an audit chain can be exported as self-contained evidence with its verification.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Literal

import pytest
from sqlalchemy import text

from argus.apps.cli.main import _export_chain
from argus.core.config import Settings
from argus.infrastructure.db import Database
from argus.modules.identity.administration import StatusChange, set_account_status
from tests.support import (
    STRONG_PASSWORD,
    ApiHarness,
    api_harness,
    bearer,
    create_org,
    register_and_login,
)

pytestmark = pytest.mark.integration
V1 = "/api/v1"


@pytest.fixture
async def h(db_settings: Settings) -> AsyncIterator[ApiHarness]:
    async with api_harness(db_settings) as harness:
        yield harness


def owner_database(settings: Settings) -> Database:
    assert settings.database.migration_url is not None
    return Database(settings.database.model_copy(update={"url": settings.database.migration_url}))


async def change_status(
    h: ApiHarness,
    email: str,
    status: Literal["active", "disabled"],
    reason: str = "incident 2026-10-05: credentials found in a paste site",
) -> StatusChange | None:
    return await set_account_status(
        database=h.container.database,
        audit=h.container.audit,
        sessions=h.container.sessions,
        clock=h.container.clock,
        email=email,
        status=status,
        reason=reason,
    )


async def disable(
    h: ApiHarness, email: str, status: Literal["active", "disabled"] = "disabled"
) -> int:
    change = await change_status(h, email, status)
    assert change is not None
    return change.sessions_revoked


async def test_disabling_an_account_stops_sessions_sign_in_and_api_keys(
    h: ApiHarness, db_settings: Settings
) -> None:
    email, tokens = await register_and_login(h)
    token = tokens["access_token"]
    org = await create_org(h, token)
    key = await h.client.post(
        f"{V1}/orgs/{org['id']}/api-keys",
        json={"name": "automation", "scopes": ["org:read"]},
        headers=bearer(token),
    )
    api_key = key.json()["key"]
    assert (
        await h.client.get(f"{V1}/orgs/{org['id']}", headers=bearer(api_key))
    ).status_code == 200

    assert await disable(h, email) >= 1
    assert (await h.client.get(f"{V1}/auth/me", headers=bearer(token))).status_code == 401
    assert (
        await h.client.get(f"{V1}/orgs/{org['id']}", headers=bearer(api_key))
    ).status_code == 401
    refresh = await h.client.post(
        f"{V1}/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert refresh.status_code == 401
    login = await h.client.post(
        f"{V1}/auth/login", json={"email": email, "password": STRONG_PASSWORD}
    )
    assert login.status_code in {401, 403}

    # Re-enabling restores sign-in and keys, never the revoked session.
    assert await disable(h, email, "active") == 0
    assert (await h.client.get(f"{V1}/auth/me", headers=bearer(token))).status_code == 401
    again = await h.client.post(
        f"{V1}/auth/login", json={"email": email, "password": STRONG_PASSWORD}
    )
    assert again.status_code == 200, again.text
    assert (
        await h.client.get(f"{V1}/orgs/{org['id']}", headers=bearer(api_key))
    ).status_code == 200

    owner = owner_database(db_settings)
    try:
        async with owner.session(read_only=True) as session:
            actions = (
                await session.execute(
                    text(
                        "SELECT action FROM audit_logs WHERE chain_key = 'platform'"
                        " AND target_id = (SELECT id::text FROM users WHERE email = :email)"
                        " AND action LIKE 'user.%abled' ORDER BY chain_seq"
                    ),
                    {"email": email},
                )
            ).scalars()
            assert list(actions) == ["user.disabled", "user.enabled"]
    finally:
        await owner.dispose()


async def test_unknown_accounts_and_missing_reasons_are_refused(h: ApiHarness) -> None:
    assert await change_status(h, "nobody@example.com", "disabled") is None
    email, _ = await register_and_login(h)
    with pytest.raises(ValueError, match="reason"):
        await change_status(h, email, "disabled", reason=" ")


async def test_an_audit_chain_exports_as_verifiable_evidence(
    h: ApiHarness, db_settings: Settings, tmp_path: Path
) -> None:
    _, tokens = await register_and_login(h)
    org = await create_org(h, tokens["access_token"])
    owner = owner_database(db_settings)
    target = tmp_path / "evidence.jsonl"
    try:
        with target.open("x", encoding="utf-8") as handle:
            status = await _export_chain(owner, h.container.audit, org["id"], handle)
    finally:
        await owner.dispose()
    assert status == 0
    lines = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
    events, verification = lines[:-1], lines[-1]["verification"]
    assert verification["valid"] is True
    assert verification["events"] == len(events) >= 1
    assert [event["chain_seq"] for event in events] == list(range(1, len(events) + 1))
    assert all(len(event["hash"]) == 64 and len(event["prev_hash"]) == 64 for event in events)
    assert events[0]["prev_hash"] == "0" * 64
    assert all(event["organization_id"] == org["id"] for event in events)


async def test_workers_wait_until_the_schema_is_current(
    h: ApiHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    from argus.apps import process

    stop = asyncio.Event()
    assert await process.wait_for_schema(h.container.database, stop, interval_s=0.05)
    # A database still behind this build: no job is claimed until it catches up (or shutdown).
    monkeypatch.setattr(process, "schema_state", lambda _current: "pending")
    asyncio.get_running_loop().call_later(0.2, stop.set)
    assert not await process.wait_for_schema(h.container.database, stop, interval_s=0.05)
