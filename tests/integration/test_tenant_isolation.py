"""Tenant isolation: the three independent layers (ADR 0002) each stop a cross-tenant leak.

1. API / service layer - foreign organisation and project ids answer 404, never 403.
2. PostgreSQL RLS - even raw SQL as the runtime role sees and changes only its own tenant, and
   sees nothing at all without a tenant context.
3. Composite foreign keys - rows cannot reference another tenant's rows.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from argus.core.config import Settings
from argus.core.ids import uuid7
from argus.infrastructure.db import Database
from tests.support import ApiHarness, api_harness, bearer, register_and_login

pytestmark = [pytest.mark.integration, pytest.mark.security]
V1 = "/api/v1"


@dataclass
class Tenant:
    token: str
    user_id: str
    org: dict[str, Any]
    project: dict[str, Any]
    key: str


async def _tenant(h: ApiHarness, name: str) -> Tenant:
    _, tokens = await register_and_login(h)
    token = tokens["access_token"]
    me = (await h.client.get(f"{V1}/auth/me", headers=bearer(token))).json()
    org = (await h.client.post(f"{V1}/orgs", json={"name": name}, headers=bearer(token))).json()
    project = (
        await h.client.post(
            f"{V1}/orgs/{org['id']}/projects",
            json={"name": f"{name} project"},
            headers=bearer(token),
        )
    ).json()
    key = (
        await h.client.post(
            f"{V1}/orgs/{org['id']}/api-keys",
            json={"name": "k", "scopes": ["projects:read", "audit:read"]},
            headers=bearer(token),
        )
    ).json()["key"]
    return Tenant(token, me["id"], org, project, key)


@pytest.fixture
async def world(db_settings: Settings) -> AsyncIterator[tuple[ApiHarness, Tenant, Tenant]]:
    async with api_harness(db_settings) as h:
        a = await _tenant(h, "Alpha")
        b = await _tenant(h, "Bravo")
        yield h, a, b


# --------------------------------------------------------------------------- layer 1: API
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/orgs/{org}"),
        ("PATCH", "/orgs/{org}"),
        ("DELETE", "/orgs/{org}"),
        ("GET", "/orgs/{org}/members"),
        ("GET", "/orgs/{org}/invitations"),
        ("GET", "/orgs/{org}/api-keys"),
        ("GET", "/orgs/{org}/service-accounts"),
        ("GET", "/orgs/{org}/audit-logs"),
        ("GET", "/orgs/{org}/projects"),
        ("GET", "/orgs/{org}/projects/{project}"),
        ("PATCH", "/orgs/{org}/projects/{project}"),
        ("DELETE", "/orgs/{org}/projects/{project}"),
        ("GET", "/orgs/{org}/projects/{project}/members"),
    ],
)
async def test_foreign_organisation_resources_answer_404(
    world: tuple[ApiHarness, Tenant, Tenant], method: str, path: str
) -> None:
    h, a, b = world
    url = V1 + path.format(org=b.org["id"], project=b.project["id"])
    body = {"name": "pwned"} if method == "PATCH" else None
    for credential in (a.token, a.key):
        response = await h.client.request(method, url, json=body, headers=bearer(credential))
        assert response.status_code == 404, (credential[:12], method, url, response.text)


async def test_own_project_under_foreign_org_id_is_not_found(
    world: tuple[ApiHarness, Tenant, Tenant],
) -> None:
    h, a, b = world
    # mixing identifiers must not "find" the project through the other tenant
    response = await h.client.get(
        f"{V1}/orgs/{b.org['id']}/projects/{a.project['id']}", headers=bearer(a.token)
    )
    assert response.status_code == 404
    response = await h.client.get(
        f"{V1}/orgs/{a.org['id']}/projects/{b.project['id']}", headers=bearer(a.token)
    )
    assert response.status_code == 404


async def test_listing_my_organisations_never_includes_others(
    world: tuple[ApiHarness, Tenant, Tenant],
) -> None:
    h, a, b = world
    ids = {o["id"] for o in (await h.client.get(f"{V1}/orgs", headers=bearer(a.token))).json()}
    assert a.org["id"] in ids
    assert b.org["id"] not in ids


async def test_audit_log_is_tenant_scoped(world: tuple[ApiHarness, Tenant, Tenant]) -> None:
    h, a, b = world
    events = (
        await h.client.get(f"{V1}/orgs/{a.org['id']}/audit-logs?limit=200", headers=bearer(a.key))
    ).json()["items"]
    assert events
    assert all(b.project["id"] != e["target_id"] and b.org["id"] != e["target_id"] for e in events)


# --------------------------------------------------------------------------- layer 2: RLS
async def _db(settings: Settings) -> Database:
    return Database(settings.database)


async def test_rls_without_context_sees_nothing(
    db_settings: Settings, world: tuple[ApiHarness, Tenant, Tenant]
) -> None:
    db = await _db(db_settings)
    try:
        async with db.session() as session:
            for table in (
                "organizations",
                "projects",
                "api_keys",
                "organization_members",
                "audit_logs",
            ):
                count = (await session.execute(text(f"SELECT count(*) FROM {table}"))).scalar()  # noqa: S608
                assert count == 0, table
    finally:
        await db.dispose()


async def test_rls_with_context_sees_only_own_tenant(
    db_settings: Settings, world: tuple[ApiHarness, Tenant, Tenant]
) -> None:
    _, a, _ = world
    db = await _db(db_settings)
    try:
        async with db.session(organization_id=UUID(a.org["id"])) as session:
            orgs = set((await session.execute(text("SELECT id FROM organizations"))).scalars())
            projects = set(
                (await session.execute(text("SELECT organization_id FROM projects"))).scalars()
            )
            keys = set(
                (await session.execute(text("SELECT organization_id FROM api_keys"))).scalars()
            )
        assert orgs == {UUID(a.org["id"])}
        assert projects == {UUID(a.org["id"])}
        assert keys == {UUID(a.org["id"])}
    finally:
        await db.dispose()


async def test_rls_blocks_cross_tenant_writes(
    db_settings: Settings, world: tuple[ApiHarness, Tenant, Tenant]
) -> None:
    _, a, b = world
    db = await _db(db_settings)
    try:
        with pytest.raises(DBAPIError, match="row-level security"):
            async with db.session(organization_id=UUID(a.org["id"])) as session:
                await session.execute(
                    text(
                        "INSERT INTO projects (id, organization_id, name) VALUES (:id, :org, 'smuggled')"
                    ),
                    {"id": uuid7(), "org": UUID(b.org["id"])},
                )
        async with db.session(organization_id=UUID(a.org["id"])) as session:
            updated = await session.execute(
                text("UPDATE projects SET name = 'defaced' WHERE organization_id = :org"),
                {"org": UUID(b.org["id"])},
            )
            deleted = await session.execute(
                text("DELETE FROM api_keys WHERE organization_id = :org"),
                {"org": UUID(b.org["id"])},
            )
            assert updated.rowcount == 0  # type: ignore[attr-defined]
            assert deleted.rowcount == 0  # type: ignore[attr-defined]
    finally:
        await db.dispose()


async def _query_with_forged_context(db: Database) -> None:
    async with db.session() as session:
        await session.execute(text("SELECT set_config('argus.org_id', 'x'' OR true --', true)"))
        await session.execute(text("SELECT count(*) FROM projects"))


async def test_malformed_context_fails_closed(
    db_settings: Settings, world: tuple[ApiHarness, Tenant, Tenant]
) -> None:
    db = await _db(db_settings)
    try:
        with pytest.raises(DBAPIError, match="invalid input syntax for type uuid"):
            await _query_with_forged_context(db)
    finally:
        await db.dispose()


async def test_api_key_lookup_function_reveals_nothing_without_the_secret(
    db_settings: Settings, world: tuple[ApiHarness, Tenant, Tenant]
) -> None:
    _, a, _ = world
    key_id = a.key.split("_")[2]
    db = await _db(db_settings)
    try:
        async with db.session() as session:
            rows = (
                await session.execute(
                    text("SELECT * FROM argus_authenticate_api_key(:k, :h)"),
                    {"k": key_id, "h": b"\x00" * 32},
                )
            ).all()
        assert rows == []
    finally:
        await db.dispose()


# --------------------------------------------------------------- layer 3: composite FKs
async def test_composite_foreign_keys_prevent_cross_tenant_references(
    db_settings: Settings, world: tuple[ApiHarness, Tenant, Tenant]
) -> None:
    _, a, b = world
    db = await _db(db_settings)
    try:
        # a project member row inside tenant A that points at tenant B's project
        with pytest.raises(IntegrityError):
            async with db.session(organization_id=UUID(a.org["id"])) as session:
                await session.execute(
                    text(
                        "INSERT INTO project_members (organization_id, project_id, user_id, role) "
                        "VALUES (:org, :project, :user, 'editor')"
                    ),
                    {
                        "org": UUID(a.org["id"]),
                        "project": UUID(b.project["id"]),
                        "user": UUID(a.user_id),
                    },
                )
        # ... or at a user who is not a member of tenant A
        with pytest.raises(IntegrityError):
            async with db.session(organization_id=UUID(a.org["id"])) as session:
                await session.execute(
                    text(
                        "INSERT INTO project_members (organization_id, project_id, user_id, role) "
                        "VALUES (:org, :project, :user, 'editor')"
                    ),
                    {
                        "org": UUID(a.org["id"]),
                        "project": UUID(a.project["id"]),
                        "user": UUID(b.user_id),
                    },
                )
    finally:
        await db.dispose()
