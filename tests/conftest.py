"""Test-suite wiring.

* Unit tests need nothing external.
* Integration tests (``@pytest.mark.integration``) need ``ARGUS_TEST_DATABASE_URL`` - a PostgreSQL
  **superuser** DSN. The suite then creates a throwaway database plus two roles that mirror
  production (owner for migrations, restricted runtime role for the application), migrates as the
  owner, and runs the application as the runtime role - so RLS and grants are exercised exactly as
  in production. Without the variable, integration tests are skipped, not failed.
"""

from __future__ import annotations

import asyncio
import os
import secrets
from collections.abc import AsyncIterator, Iterator

import pytest
from sqlalchemy.engine import make_url

from argus.core.config import Settings
from tests.support import (
    TEST_APP_ROLE,
    TEST_OWNER_ROLE,
    TEST_ROLE_PASSWORD,
    DatabaseURLs,
    make_settings,
    with_credentials,
)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if "perf" not in (config.getoption("markexpr") or ""):
        not_selected = pytest.mark.skip(reason="benchmarks run only when selected: pytest -m perf")
        for item in items:
            if "perf" in item.keywords:
                item.add_marker(not_selected)
    if os.environ.get("ARGUS_TEST_DATABASE_URL"):
        return
    skip = pytest.mark.skip(reason="ARGUS_TEST_DATABASE_URL is not set (PostgreSQL superuser DSN)")
    for item in items:
        if "integration" in item.keywords or "e2e" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session", autouse=True)
def _hermetic_environment() -> Iterator[None]:
    """Settings must come from the test, never from the developer's shell or .env."""
    with pytest.MonkeyPatch.context() as mp:
        for key in list(os.environ):
            if key.upper().startswith("ARGUS_") and not key.upper().startswith("ARGUS_TEST_"):
                mp.delenv(key)
        yield


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture(scope="session")
async def database_urls() -> AsyncIterator[DatabaseURLs]:
    import asyncpg
    from alembic import command

    from argus.infrastructure.db.migrations import alembic_config

    admin_url = os.environ.get("ARGUS_TEST_DATABASE_URL")
    if not admin_url:
        pytest.skip("ARGUS_TEST_DATABASE_URL is not set")
    admin = make_url(admin_url).set(drivername="postgresql")
    plain_admin = admin.render_as_string(hide_password=False)
    name = f"argus_test_{secrets.token_hex(4)}"
    conn = await asyncpg.connect(plain_admin)
    try:
        for role, attrs in (
            (TEST_OWNER_ROLE, "LOGIN"),
            (TEST_APP_ROLE, "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"),
        ):
            if not await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", role):
                await conn.execute(f"CREATE ROLE {role} {attrs} PASSWORD '{TEST_ROLE_PASSWORD}'")
        await conn.execute(f"CREATE DATABASE {name} OWNER {TEST_OWNER_ROLE}")
    finally:
        await conn.close()

    db_admin = with_credentials(
        plain_admin,
        user=admin.username or "postgres",
        password=admin.password,
        database=name,
        driver="postgresql",
    )
    conn = await asyncpg.connect(db_admin)
    try:
        await conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
    finally:
        await conn.close()

    urls = DatabaseURLs(
        admin=db_admin,
        owner=with_credentials(
            plain_admin,
            user=TEST_OWNER_ROLE,
            password=TEST_ROLE_PASSWORD,
            database=name,
            driver="postgresql+asyncpg",
        ),
        app=with_credentials(
            plain_admin,
            user=TEST_APP_ROLE,
            password=TEST_ROLE_PASSWORD,
            database=name,
            driver="postgresql+asyncpg",
        ),
        name=name,
    )
    migrate_settings = make_settings(
        database={"url": urls.app, "migration_url": urls.owner, "app_role": TEST_APP_ROLE}
    )
    await asyncio.to_thread(command.upgrade, alembic_config(migrate_settings), "head")
    try:
        yield urls
    finally:
        conn = await asyncpg.connect(plain_admin)
        try:
            await conn.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = $1 AND pid <> pg_backend_pid()",
                name,
            )
            await conn.execute(f"DROP DATABASE IF EXISTS {name}")
        finally:
            await conn.close()


@pytest.fixture
def db_settings(database_urls: DatabaseURLs) -> Settings:
    return make_settings(
        database={
            "url": database_urls.app,
            "migration_url": database_urls.owner,
            "app_role": TEST_APP_ROLE,
        }
    )
