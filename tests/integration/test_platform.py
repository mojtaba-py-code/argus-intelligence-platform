"""Phase 24 acceptance: plans and quotas, retention, organisation lifecycle, exports, dashboard.

Plans are code; an organisation is put on the ``free`` plan with SQL (what ``argus orgs set-plan``
does) so its small limits can be reached. Everything else goes through the public API, the
worker and the scheduler duties, on the runtime role with row-level security.
"""

from __future__ import annotations

import asyncio
import io
import json
import zipfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import asyncpg
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from argus.apps.cli.main import _prune_chain
from argus.apps.worker.main import build_worker
from argus.core.config import Settings
from argus.infrastructure.db import Database
from argus.modules.platform.exports import DOWNLOAD_SLOTS
from argus.modules.platform.lifecycle import LifecycleError
from argus.modules.platform.retention import RetentionReport
from tests.research_world import World, open_world
from tests.support import (
    STRONG_PASSWORD,
    ApiHarness,
    DatabaseURLs,
    MutableClock,
    api_harness,
    bearer,
    create_org,
    create_project,
    join_org,
    register_and_login,
)

pytestmark = pytest.mark.integration
V1 = "/api/v1"


@pytest.fixture
async def h(db_settings: Settings) -> AsyncIterator[ApiHarness]:
    async with api_harness(db_settings) as harness:
        yield harness


async def owner_org(h: ApiHarness) -> tuple[str, str]:
    _, tokens = await register_and_login(h)
    org = await create_org(h, tokens["access_token"])
    return tokens["access_token"], str(org["id"])


async def login(h: ApiHarness, email: str) -> str:
    response = await h.client.post(
        f"{V1}/auth/login", json={"email": email, "password": STRONG_PASSWORD}
    )
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


async def sql(urls: DatabaseURLs, statement: str, *args: Any) -> Any:
    conn = await asyncpg.connect(urls.admin)
    try:
        return await conn.fetch(statement, *args)
    finally:
        await conn.close()


def owner_database(settings: Settings) -> Database:
    assert settings.database.migration_url is not None
    return Database(settings.database.model_copy(update={"url": settings.database.migration_url}))


# ------------------------------------------------------------------------------- quotas
async def test_free_plan_quotas_are_enforced_and_reported(
    h: ApiHarness, database_urls: DatabaseURLs
) -> None:
    owner, org_id = await owner_org(h)
    _, viewer = await join_org(h, owner, org_id, "viewer")
    await sql(database_urls, "UPDATE organizations SET plan = 'free' WHERE id = $1", UUID(org_id))
    projects = f"{V1}/orgs/{org_id}/projects"

    for index in range(3):
        await create_project(h, owner, org_id, f"Project {index}")
    refused = await h.client.post(projects, json={"name": "One too many"}, headers=bearer(owner))
    assert refused.status_code == 403
    assert refused.json()["code"] == "quota_exceeded"
    assert "free plan allows 3 projects" in refused.json()["detail"]

    keys = f"{V1}/orgs/{org_id}/api-keys"
    for index in range(5):
        created = await h.client.post(
            keys, json={"name": f"k{index}", "scopes": ["org:read"]}, headers=bearer(owner)
        )
        assert created.status_code == 201, created.text
    extra = await h.client.post(
        keys, json={"name": "k6", "scopes": ["org:read"]}, headers=bearer(owner)
    )
    assert extra.json()["code"] == "quota_exceeded"

    # Members: the owner, the viewer and three invitations fill five seats.
    invitations = f"{V1}/orgs/{org_id}/invitations"
    for index in range(3):
        sent = await h.client.post(
            invitations,
            json={"email": f"seat{index}.{org_id[:8]}@example.com", "role": "viewer"},
            headers=bearer(owner),
        )
        assert sent.status_code == 201, sent.text
    full = await h.client.post(
        invitations,
        json={"email": f"seat9.{org_id[:8]}@example.com", "role": "viewer"},
        headers=bearer(owner),
    )
    assert full.json()["code"] == "quota_exceeded"
    # Re-sending an invitation replaces the open one: it needs no free seat.
    resent = await h.client.post(
        invitations,
        json={"email": f"seat0.{org_id[:8]}@example.com", "role": "analyst"},
        headers=bearer(owner),
    )
    assert resent.status_code == 201, resent.text

    usage = await h.client.get(f"{V1}/orgs/{org_id}/usage", headers=bearer(owner))
    assert usage.status_code == 200, usage.text
    body = usage.json()
    assert body["plan"] == "free"
    assert body["metrics"]["projects"] == {"used": 3, "limit": 3}
    assert body["metrics"]["api_keys"] == {"used": 5, "limit": 5}
    assert body["metrics"]["members"] == {"used": 5, "limit": 5}
    assert body["llm"]["plan_ceiling_usd"] == 25.0
    assert body["llm"]["budget_usd"] == 25.0  # the default $100 budget is capped by the plan
    assert (
        await h.client.get(f"{V1}/orgs/{org_id}/usage", headers=bearer(viewer))
    ).status_code == 403

    # An organisation cannot raise its own budget above the plan's ceiling.
    update = f"{V1}/orgs/{org_id}"
    budgets = {"monthly_llm_usd": 100.0, "job_default_usd": 5.0, "approval_threshold_usd": 20.0}
    too_much = await h.client.patch(update, json={"budgets": budgets}, headers=bearer(owner))
    assert too_much.status_code == 422
    budgets["monthly_llm_usd"] = 20.0
    assert (
        await h.client.patch(update, json={"budgets": budgets}, headers=bearer(owner))
    ).status_code == 200


async def test_concurrent_requests_cannot_both_take_the_last_slot(
    h: ApiHarness, database_urls: DatabaseURLs
) -> None:
    owner, org_id = await owner_org(h)
    await sql(database_urls, "UPDATE organizations SET plan = 'free' WHERE id = $1", UUID(org_id))
    for index in range(2):
        await create_project(h, owner, org_id, f"Existing {index}")
    url = f"{V1}/orgs/{org_id}/projects"
    responses = await asyncio.gather(
        *(h.client.post(url, json={"name": f"Race {i}"}, headers=bearer(owner)) for i in range(4))
    )
    assert sorted(r.status_code for r in responses) == [201, 403, 403, 403]


async def test_research_and_storage_quotas(world: World, database_urls: DatabaseURLs) -> None:
    org = UUID(world.org_id)
    await sql(database_urls, "UPDATE organizations SET plan = 'free' WHERE id = $1", org)
    await sql(
        database_urls,
        "INSERT INTO research_jobs (id, organization_id, project_id, title, objective, mode,"
        " status, budget_usd, max_sources) SELECT gen_random_uuid(), $1, $2, 'old', 'old',"
        " 'web', 'completed', 1, 1 FROM generate_series(1, 50)",
        org,
        UUID(world.project_id),
    )
    refused = await world.h.client.post(
        f"{world.base}/research-jobs",
        json={"objective": "One more analysis of the support market"},
        headers=bearer(world.owner),
    )
    assert refused.status_code == 403
    assert "research jobs per month" in refused.json()["detail"]

    await sql(
        database_urls,
        "INSERT INTO documents (id, organization_id, project_id, filename, kind, media_type,"
        " byte_size, sha256, storage_key, classification, status) VALUES (gen_random_uuid(),"
        " $1, $2, 'big.txt', 'text', 'text/plain', $3, sha256('quota'::bytea),"
        " 'perf/' || gen_random_uuid(), 1, 'ready')",
        org,
        UUID(world.project_id),
        1024**3 - 10,
    )
    upload = await world.h.client.post(
        f"{world.base}/documents",
        files={"file": ("notes.txt", b"more than ten bytes of text", "text/plain")},
        headers=bearer(world.owner),
    )
    assert upload.status_code == 403
    assert "document storage" in upload.json()["detail"]


@pytest.fixture
async def world(db_settings: Settings, tmp_path: Path) -> AsyncIterator[World]:
    async with open_world(db_settings, tmp_path) as opened:
        yield opened


# ---------------------------------------------------------------------------- retention
async def test_retention_keeps_current_content_and_prunes_audit_behind_a_checkpoint(
    db_settings: Settings, database_urls: DatabaseURLs
) -> None:
    clock = MutableClock(datetime.now(UTC) - timedelta(days=200))
    async with api_harness(db_settings, clock=clock) as h:
        email, tokens = await register_and_login(h)  # audit events 200 days old
        owner = tokens["access_token"]
        org_id = str((await create_org(h, owner))["id"])
        org = UUID(org_id)
        project = await create_project(h, owner, org_id)
        clock.advance(200 * 86_400)
        owner = await login(h, email)
        source = (
            await sql(
                database_urls,
                "INSERT INTO sources (id, organization_id, project_id, url, url_hash, domain,"
                " status) VALUES (gen_random_uuid(), $1, $2, 'https://a.example.com/', sha256('r'::bytea),"
                " 'a.example.com', 'fetched') RETURNING id",
                org,
                UUID(project["id"]),
            )
        )[0]["id"]
        returning = (
            await sql(
                database_urls,
                "INSERT INTO sources (id, organization_id, project_id, url, url_hash, domain,"
                " status) VALUES (gen_random_uuid(), $1, $2, 'https://b.example.com/',"
                " sha256('b'::bytea), 'b.example.com', 'fetched') RETURNING id",
                org,
                UUID(project["id"]),
            )
        )[0]["id"]
        # (source, first fetched, last seen, text). The second page changed back to content
        # first seen 300 days ago: that version is the current one, not the 200-day-old one.
        versions = (
            (source, 300, 300, "old"),
            (source, 200, 200, "older-current"),
            (source, 150, 150, "newest"),
            (returning, 300, 150, "came back"),
            (returning, 200, 200, "in between"),
        )
        for owner_source, fetched, seen, label in versions:
            await sql(
                database_urls,
                "INSERT INTO source_snapshots (id, organization_id, source_id, fetched_at,"
                " last_seen_at, final_url, http_status, media_type, content_hash, byte_size, text)"
                " VALUES (gen_random_uuid(), $1, $2, now() - make_interval(days => $3),"
                " now() - make_interval(days => $4), 'https://a.example.com/', 200, 'text/html',"
                " sha256(convert_to($5::text, 'UTF8')), 1, $5::text)",
                org,
                owner_source,
                fetched,
                seen,
                label,
            )
        await sql(
            database_urls,
            "INSERT INTO llm_requests (id, organization_id, task, prompt_name, prompt_version,"
            " prompt_sha256, provider, model, locality, classification, outcome, created_at)"
            " VALUES (gen_random_uuid(), $1, 't', 'p', 1, repeat('0', 64), 'local', 'm', 'local',"
            " 1, 'ok', now() - interval '500 days')",
            org,
        )
        settings: dict[str, object] = {"retention": {"raw_snapshots_days": 90, "audit_days": 90}}
        report = RetentionReport()
        await h.container.retention.organization(org, settings, report)

        texts = sorted(
            row["text"]
            for row in await sql(
                database_urls, "SELECT text FROM source_snapshots WHERE source_id = $1", source
            )
        )
        assert texts == ["newest"]  # the current version stays, superseded ones go
        kept = await sql(
            database_urls, "SELECT text FROM source_snapshots WHERE source_id = $1", returning
        )
        assert [row["text"] for row in kept] == ["came back"]
        assert report.deleted["snapshots"] == 3
        assert report.deleted["llm_requests"] == 1
        assert report.deleted["audit_events"] >= 2

        owner_db = owner_database(db_settings)
        try:
            async with owner_db.session(read_only=True) as session:
                result = await h.container.audit.verify_chain(session, org_id)
            assert result.valid, result
            # The chain keeps growing from its checkpoint.
            created = await h.client.post(
                f"{V1}/orgs/{org_id}/projects", json={"name": "After"}, headers=bearer(owner)
            )
            assert created.status_code == 201
            async with owner_db.session(read_only=True) as session:
                assert (await h.container.audit.verify_chain(session, org_id)).valid
        finally:
            await owner_db.dispose()

        # Pruning freed the sequence numbers below the checkpoint: no row may be added there.
        forge = (
            "INSERT INTO audit_logs (chain_key, chain_seq, organization_id, occurred_at, action,"
            " category, outcome, actor_type, actor_id, user_id, target_type, target_id,"
            " request_id, ip_address, user_agent, details, prev_hash, hash)"
            " SELECT chain_key, 1, organization_id, occurred_at, 'auth.login', category,"
            " outcome, actor_type, actor_id, user_id, target_type, target_id, request_id,"
            " ip_address, user_agent, details, prev_hash, hash FROM audit_logs"
            " WHERE chain_key = $1 ORDER BY chain_seq DESC LIMIT 1"
        )
        with pytest.raises(asyncpg.InsufficientPrivilegeError, match="at or below a checkpoint"):
            await sql(database_urls, forge, org_id)
        # Even with the guard switched off by a superuser, verification notices the row.
        await sql(
            database_urls, "ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_above_checkpoint"
        )
        try:
            await sql(database_urls, forge, org_id)
        finally:
            await sql(
                database_urls, "ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_above_checkpoint"
            )
        owner_db = owner_database(db_settings)
        try:
            async with owner_db.session(read_only=True) as session:
                below = await h.container.audit.verify_chain(session, org_id)
        finally:
            await owner_db.dispose()
        assert (below.valid, below.reason, below.first_broken_seq) == (
            False,
            "rows below the checkpoint",
            1,
        )

        # A forged checkpoint is detected.
        await sql(
            database_urls,
            "ALTER TABLE audit_checkpoints DISABLE TRIGGER audit_checkpoints_append_only",
        )
        try:
            await sql(
                database_urls,
                "UPDATE audit_checkpoints SET mac = sha256('forged'::bytea) WHERE chain_key = $1",
                org_id,
            )
        finally:
            await sql(
                database_urls,
                "ALTER TABLE audit_checkpoints ENABLE TRIGGER audit_checkpoints_append_only",
            )
        owner_db = owner_database(db_settings)
        try:
            async with owner_db.session(read_only=True) as session:
                forged = await h.container.audit.verify_chain(session, org_id)
        finally:
            await owner_db.dispose()
        assert (forged.valid, forged.reason) == (False, "checkpoint forged")


async def test_the_database_refuses_unsafe_audit_pruning(
    h: ApiHarness, database_urls: DatabaseURLs
) -> None:
    owner, org_id = await owner_org(h)
    _, other_org = await owner_org(h)
    del owner
    newest = (
        await sql(
            database_urls,
            "SELECT chain_seq, hash FROM audit_logs WHERE chain_key = $1"
            " ORDER BY chain_seq DESC LIMIT 1",
            org_id,
        )
    )[0]
    mac = h.container.audit.checkpoint_mac(org_id, newest["chain_seq"], bytes(newest["hash"]))
    call = "SELECT argus_prune_audit(:chain, :seq, :hash, :mac)"
    params = {
        "chain": org_id,
        "seq": newest["chain_seq"],
        "hash": bytes(newest["hash"]),
        "mac": mac,
    }
    with pytest.raises(DBAPIError, match="younger than 90 days"):
        async with h.container.database.session(organization_id=UUID(org_id)) as session:
            await session.execute(text(call), params)
    with pytest.raises(DBAPIError, match="only its own audit chain"):
        async with h.container.database.session(organization_id=UUID(other_org)) as session:
            await session.execute(text(call), params)
    with pytest.raises(DBAPIError, match="schema owner only"):
        async with h.container.database.session() as session:
            await session.execute(text(call), {**params, "chain": "platform"})
    with pytest.raises(DBAPIError, match="does not match"):
        async with h.container.database.session(organization_id=UUID(org_id)) as session:
            await session.execute(text(call), {**params, "hash": b"\x00" * 32})
    # And the runtime role still cannot delete audit rows by itself.
    with pytest.raises(DBAPIError):
        async with h.container.database.session(organization_id=UUID(org_id)) as session:
            await session.execute(
                text("DELETE FROM audit_logs WHERE chain_key = :c"), {"c": org_id}
            )


async def test_operators_cannot_prune_less_than_a_chain_is_owed(
    h: ApiHarness, db_settings: Settings, capsys: pytest.CaptureFixture[str]
) -> None:
    owner, org_id = await owner_org(h)
    updated = await h.client.patch(
        f"{V1}/orgs/{org_id}", json={"retention": {"audit_days": 400}}, headers=bearer(owner)
    )
    assert updated.status_code == 200, updated.text
    owner_db = owner_database(db_settings)
    audit = h.container.audit
    try:
        assert await _prune_chain(owner_db, audit, org_id.upper(), 120, db_settings) == 2
        assert "keeps 400 days" in capsys.readouterr().err
        assert await _prune_chain(owner_db, audit, "platform", 120, db_settings) == 2
        assert "keeps 730 days" in capsys.readouterr().err
        unknown = "00000000-0000-0000-0000-000000000001"
        assert await _prune_chain(owner_db, audit, unknown, 900, db_settings) == 2
        assert "there is no audit chain" in capsys.readouterr().err
        assert await _prune_chain(owner_db, audit, "not-a-chain", 900, db_settings) == 2
        # Owed retention respected: nothing old enough yet, and that is a success.
        assert await _prune_chain(owner_db, audit, org_id.upper(), 400, db_settings) == 0
    finally:
        await owner_db.dispose()


async def test_retention_sweep_covers_every_organisation(h: ApiHarness) -> None:
    await owner_org(h)
    report = await h.container.retention.sweep()
    assert report.organizations >= 1


# ---------------------------------------------------------------------------- lifecycle
async def test_suspension_deletion_restore_and_purge(
    world: World, db_settings: Settings, database_urls: DatabaseURLs
) -> None:
    h, org_id, owner = world.h, world.org_id, world.owner
    org = UUID(org_id)
    lifecycle = h.container.lifecycle
    key = (await world.api_key(["org:read"]))["key"]
    document_id = await world.upload("evidence.txt", b"Vendor A leads the market. " * 10)
    blob_key = (
        await sql(
            database_urls, "SELECT storage_key FROM documents WHERE id = $1", UUID(document_id)
        )
    )[0]["storage_key"]
    assert await h.container.storage.exists(blob_key)

    await lifecycle.suspend(org, reason="unpaid invoice")
    assert (await h.client.get(f"{V1}/orgs/{org_id}", headers=bearer(owner))).status_code == 403
    assert (await h.client.get(f"{V1}/orgs/{org_id}", headers=bearer(key))).status_code == 401
    await lifecycle.resume(org, reason="paid")
    assert (await h.client.get(f"{V1}/orgs/{org_id}", headers=bearer(owner))).status_code == 200

    deleted = await h.client.delete(f"{V1}/orgs/{org_id}", headers=bearer(owner))
    assert deleted.status_code == 202
    assert (await h.client.get(f"{V1}/orgs/{org_id}", headers=bearer(owner))).status_code == 404
    with pytest.raises(ValueError, match="grace period"):
        await lifecycle.purge(org)
    await lifecycle.restore(org, reason="deleted by mistake")
    assert (await h.client.get(f"{V1}/orgs/{org_id}", headers=bearer(owner))).status_code == 200

    await h.client.delete(f"{V1}/orgs/{org_id}", headers=bearer(owner))
    await sql(
        database_urls,
        "UPDATE organizations SET deletion_requested_at = now() - interval '31 days' WHERE id = $1",
        org,
    )
    # The first purge dies while deleting files: the organisation is past the point of no
    # return (it cannot be restored with files missing), invisible to members, and the next
    # scheduled run finishes the job.
    storage = h.container.storage
    real_delete = storage.delete

    async def failing_delete(key: str) -> None:
        raise OSError("storage unavailable")

    storage.delete = failing_delete  # type: ignore[method-assign]
    try:
        with pytest.raises(OSError, match="storage unavailable"):
            await lifecycle.purge(org)
    finally:
        storage.delete = real_delete  # type: ignore[method-assign]
    status = await sql(database_urls, "SELECT status FROM organizations WHERE id = $1", org)
    assert status[0]["status"] == "purging"
    with pytest.raises(LifecycleError):
        await lifecycle.restore(org, reason="too late")
    assert (await h.client.get(f"{V1}/orgs/{org_id}", headers=bearer(owner))).status_code == 404
    assert await lifecycle.purge_due() >= 1
    assert await sql(database_urls, "SELECT 1 FROM organizations WHERE id = $1", org) == []
    assert await sql(database_urls, "SELECT 1 FROM documents WHERE organization_id = $1", org) == []
    assert not await h.container.storage.exists(blob_key)
    # Audit history outlives the tenant, and the purge is on the record.
    assert await sql(database_urls, "SELECT 1 FROM audit_logs WHERE chain_key = $1 LIMIT 1", org_id)
    purged = await sql(
        database_urls,
        "SELECT 1 FROM audit_logs WHERE chain_key = 'platform' AND action = 'org.purged'"
        " AND target_id = $1",
        org_id,
    )
    assert purged


# ------------------------------------------------------------------------------ exports
async def test_owners_export_everything_the_organisation_owns_and_nothing_else(
    world: World, database_urls: DatabaseURLs
) -> None:
    h, org_id, owner = world.h, world.org_id, world.owner
    _, admin = await join_org(h, owner, org_id, "admin")
    _, other = await register_and_login(h)
    other_org = await create_org(h, other["access_token"], "Other Tenant Secret Co")
    await create_project(h, other["access_token"], other_org["id"], "Other tenant project")
    document_id = await world.upload("../../etc/notes.txt", b"Board notes: renewal approved.")
    exports = f"{V1}/orgs/{org_id}/exports"

    assert (await h.client.post(exports, headers=bearer(admin))).status_code == 403
    requested = await h.client.post(exports, headers=bearer(owner))
    assert requested.status_code == 202, requested.text
    assert requested.json()["status"] == "pending"
    assert (await h.client.post(exports, headers=bearer(owner))).status_code == 409

    await build_worker(h.container, queues=("default",)).run_until_idle()
    listed = (await h.client.get(exports, headers=bearer(owner))).json()
    assert listed[0]["status"] == "ready", listed
    assert listed[0]["documents_included"] is True
    notes = await h.client.get(f"{V1}/orgs/{org_id}/notifications", headers=bearer(owner))
    assert "platform.export.ready" in [n["event"] for n in notes.json()["items"]]

    download = await h.client.get(f"{exports}/{listed[0]['id']}/download", headers=bearer(owner))
    assert download.status_code == 200
    assert download.headers["content-type"] == "application/zip"
    assert download.headers["cache-control"] == "no-store"
    archive = zipfile.ZipFile(io.BytesIO(download.content))
    names = archive.namelist()
    assert all(not name.startswith("/") and ".." not in name.split("/") for name in names)
    manifest = json.loads(archive.read("manifest.json"))
    assert manifest["format"] == "argus.export/1"
    assert manifest["audit_chain"]["valid"] is True
    document_entry = next(name for name in names if name.startswith(f"documents/{document_id}/"))
    assert archive.read(document_entry) == b"Board notes: renewal approved."
    assert ".." not in document_entry
    everything = b"".join(archive.read(name) for name in names)
    assert b"Other tenant project" not in everything
    assert b"Other Tenant Secret Co" not in everything
    for internal in (b"password_hash", b"secret_hash", b"token_hash", b"embedding"):
        assert internal not in everything
    audit_lines = archive.read("audit.jsonl").splitlines()
    assert all(json.loads(line)["chain_key"] == org_id for line in audit_lines)

    # At most DOWNLOAD_SLOTS archives are decrypted at once per process.
    slots = h.container.exports._downloads
    for _ in range(DOWNLOAD_SLOTS):
        await slots.acquire()
    try:
        busy = await h.client.get(f"{exports}/{listed[0]['id']}/download", headers=bearer(owner))
    finally:
        for _ in range(DOWNLOAD_SLOTS):
            slots.release()
    assert busy.status_code == 429

    # Expired exports disappear with their archive.
    blob = f"org/{org_id}/exports/{listed[0]['id']}"
    assert await h.container.storage.exists(blob)
    await sql(
        database_urls,
        "UPDATE organization_exports SET expires_at = now() - interval '1 day' WHERE id = $1",
        UUID(listed[0]["id"]),
    )
    report = RetentionReport()
    await h.container.retention.organization(UUID(org_id), {}, report)
    assert report.deleted["exports"] == 1
    assert not await h.container.storage.exists(blob)
    gone = await h.client.get(f"{exports}/{listed[0]['id']}/download", headers=bearer(owner))
    assert gone.status_code == 404


async def test_exports_leave_out_quarantined_files_and_survive_a_damaged_one(
    world: World, database_urls: DatabaseURLs
) -> None:
    h, org_id, owner = world.h, world.org_id, world.owner
    good = await world.upload("good.txt", b"Kept: the renewal was approved.")
    infected = await world.upload("infected.txt", b"Quarantined content.")
    damaged = await world.upload("damaged.txt", b"Its stored file is gone.")
    await sql(
        database_urls, "UPDATE documents SET status = 'quarantined' WHERE id = $1", UUID(infected)
    )
    key = await sql(database_urls, "SELECT storage_key FROM documents WHERE id = $1", UUID(damaged))
    await h.container.storage.delete(key[0]["storage_key"])

    exports = f"{V1}/orgs/{org_id}/exports"
    assert (await h.client.post(exports, headers=bearer(owner))).status_code == 202
    await build_worker(h.container, queues=("default",)).run_until_idle()
    listed = (await h.client.get(exports, headers=bearer(owner))).json()
    assert listed[0]["status"] == "ready", listed
    download = await h.client.get(f"{exports}/{listed[0]['id']}/download", headers=bearer(owner))
    archive = zipfile.ZipFile(io.BytesIO(download.content))
    names = archive.namelist()
    assert any(name.startswith(f"documents/{good}/") for name in names)
    assert not any(name.startswith(f"documents/{infected}/") for name in names)
    assert not any(name.startswith(f"documents/{damaged}/") for name in names)
    manifest = json.loads(archive.read("manifest.json"))
    assert manifest["documents_skipped"] == [{"id": damaged, "reason": "unreadable"}]


async def test_concurrent_export_requests_start_only_one(world: World) -> None:
    h, org_id, owner = world.h, world.org_id, world.owner
    url = f"{V1}/orgs/{org_id}/exports"
    responses = await asyncio.gather(*(h.client.post(url, headers=bearer(owner)) for _ in range(3)))
    assert sorted(r.status_code for r in responses) == [202, 409, 409]


async def test_a_failed_build_is_retried_and_a_lost_one_does_not_block_the_next(
    world: World, database_urls: DatabaseURLs, monkeypatch: pytest.MonkeyPatch
) -> None:
    h, org_id, owner = world.h, world.org_id, world.owner
    exports = f"{V1}/orgs/{org_id}/exports"
    first = (await h.client.post(exports, headers=bearer(owner))).json()

    async def unavailable(organization_id: UUID) -> tuple[bytes, bool]:
        raise RuntimeError("storage unavailable")

    service = h.container.exports
    monkeypatch.setattr(service, "_archive", unavailable)

    async def status() -> dict[str, Any]:
        rows = (await h.client.get(exports, headers=bearer(owner))).json()
        return next(row for row in rows if row["id"] == first["id"])

    with pytest.raises(RuntimeError):
        await service.build(UUID(org_id), UUID(first["id"]), final_attempt=False)
    assert (await status())["status"] == "pending"  # the retry will rebuild it
    with pytest.raises(RuntimeError):
        await service.build(UUID(org_id), UUID(first["id"]), final_attempt=True)
    assert ((await status())["status"], (await status())["error_code"]) == (
        "failed",
        "build_failed",
    )

    # A build lost with its worker leaves "pending" behind; after a few hours it stops blocking.
    second = (await h.client.post(exports, headers=bearer(owner))).json()
    await sql(
        database_urls,
        "UPDATE organization_exports SET created_at = now() - interval '4 hours' WHERE id = $1",
        UUID(second["id"]),
    )
    third = await h.client.post(exports, headers=bearer(owner))
    assert third.status_code == 202, third.text
    rows = {row["id"]: row for row in (await h.client.get(exports, headers=bearer(owner))).json()}
    assert (rows[second["id"]]["status"], rows[second["id"]]["error_code"]) == (
        "failed",
        "timed_out",
    )
    # Three requests a day per organisation.
    assert (await h.client.post(exports, headers=bearer(owner))).status_code == 429


# ---------------------------------------------------------------------------- dashboard
async def test_dashboard_respects_what_each_viewer_may_see(world: World) -> None:
    h, org_id, owner = world.h, world.org_id, world.owner
    _, analyst = await join_org(h, owner, org_id, "analyst")
    job = await world.create_job()
    await world.run_jobs()
    # Created after the worker ran, so it stays queued: an "active" job only some may see.
    restricted = await h.client.post(
        f"{V1}/orgs/{org_id}/projects",
        json={"name": "Board matters", "visibility": "restricted"},
        headers=bearer(owner),
    )
    assert restricted.status_code == 201
    secret_job = await h.client.post(
        f"{V1}/orgs/{org_id}/projects/{restricted.json()['id']}/research-jobs",
        json={"objective": "Confidential acquisition target analysis for the board"},
        headers=bearer(owner),
    )
    assert secret_job.status_code == 202

    owner_view = (await h.client.get(f"{V1}/orgs/{org_id}/dashboard", headers=bearer(owner))).json()
    assert owner_view["projects"]["count"] == 2
    assert owner_view["system"]["database"] == "ok"
    assert owner_view["ai_usage"] is not None
    assert owner_view["security"] is not None
    assert any(r["job_id"] == job["id"] for r in owner_view["reports"])
    assert any(j["id"] == secret_job.json()["id"] for j in owner_view["jobs"]["active"])

    # An API key sees only the sections its scopes cover - even its admin owner's key.
    narrow = (await world.api_key(["org:read"]))["key"]
    key_view = (await h.client.get(f"{V1}/orgs/{org_id}/dashboard", headers=bearer(narrow))).json()
    for section in ("projects", "jobs", "reports", "sources", "knowledge", "monitoring"):
        assert key_view[section] is None, section
    assert key_view["ai_usage"] is None
    assert key_view["security"] is None
    assert "Board matters" not in json.dumps(key_view)
    assert "Confidential acquisition" not in json.dumps(key_view)
    projects_only = (await world.api_key(["org:read", "projects:read"]))["key"]
    scoped = (
        await h.client.get(f"{V1}/orgs/{org_id}/dashboard", headers=bearer(projects_only))
    ).json()
    assert scoped["projects"]["count"] == 2
    assert scoped["jobs"] is None
    assert scoped["reports"] is None

    analyst_view = (
        await h.client.get(f"{V1}/orgs/{org_id}/dashboard", headers=bearer(analyst))
    ).json()
    assert analyst_view["projects"]["count"] == 1
    assert all(p["name"] != "Board matters" for p in analyst_view["projects"]["recent"])
    assert all(j["id"] != secret_job.json()["id"] for j in analyst_view["jobs"]["active"])
    assert analyst_view["ai_usage"] is None
    assert analyst_view["security"] is None
    assert "Confidential acquisition" not in json.dumps(analyst_view)
