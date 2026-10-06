"""Phase 1 acceptance against real PostgreSQL, running as the restricted runtime role."""

from __future__ import annotations

import httpx
import pytest
from asgi_lifespan import LifespanManager
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from argus.apps.api.main import create_app
from argus.apps.container import build_container
from argus.core.config import Settings
from argus.core.ids import uuid7
from argus.infrastructure.db import Database

pytestmark = pytest.mark.integration


async def test_readiness_is_green_on_a_migrated_database(db_settings: Settings) -> None:
    container = build_container(db_settings, role="api")
    app = create_app(db_settings, container=container)
    async with (
        LifespanManager(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client,
    ):
        response = await client.get("/health/ready")
    await container.aclose()
    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "checks": {"database": "ok", "migrations": "ok", "redis": "disabled"},
    }


async def test_runtime_role_is_least_privileged(db_settings: Settings) -> None:
    db = Database(db_settings.database)
    try:
        async with db.session() as session:
            row = (
                await session.execute(
                    text(
                        "SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole "
                        "FROM pg_roles WHERE rolname = current_user"
                    )
                )
            ).one()
            assert tuple(row) == (False, False, False, False)
        with pytest.raises(DBAPIError, match="permission denied"):
            async with db.session() as session:
                await session.execute(text("CREATE TABLE should_not_exist (id int)"))
    finally:
        await db.dispose()


async def test_tenant_context_is_transaction_local(db_settings: Settings) -> None:
    db = Database(db_settings.database)
    org, user = uuid7(), uuid7()
    try:
        async with db.session() as session:
            assert (await session.execute(text("SELECT argus_current_org()"))).scalar() is None
        async with db.session(organization_id=org, user_id=user) as session:
            assert (await session.execute(text("SELECT argus_current_org()"))).scalar() == org
            assert (await session.execute(text("SELECT argus_current_user()"))).scalar() == user
        # the same pooled connection must not carry the previous tenant's context
        for _ in range(3):
            async with db.session() as session:
                assert (await session.execute(text("SELECT argus_current_org()"))).scalar() is None
    finally:
        await db.dispose()


async def test_connection_guards_are_applied(db_settings: Settings) -> None:
    db = Database(db_settings.database)
    try:
        async with db.session() as session:
            timeout = (await session.execute(text("SHOW statement_timeout"))).scalar()
            idle = (
                await session.execute(text("SHOW idle_in_transaction_session_timeout"))
            ).scalar()
        assert timeout == "30s"
        assert idle == "1min"
    finally:
        await db.dispose()


async def _create_in_read_only_transaction(db: Database) -> None:
    async with db.session(read_only=True) as session:
        await session.execute(text("CREATE TEMP TABLE t (id int)"))


async def test_read_only_units_of_work_reject_writes(db_settings: Settings) -> None:
    db = Database(db_settings.database)
    try:
        with pytest.raises(DBAPIError, match="read-only"):
            await _create_in_read_only_transaction(db)
    finally:
        await db.dispose()
