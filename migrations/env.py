"""Alembic environment.

Runs as the **owner** role (``ARGUS_DATABASE__MIGRATION_URL``) and tells the revisions which
runtime role to GRANT privileges to. Migrations use a generous statement timeout (index builds)
but a short lock timeout, so a migration waiting behind a long transaction fails fast instead of
queueing every application query behind its lock.
"""

from __future__ import annotations

import asyncio
from typing import Any

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from argus.core.config import Settings, load_settings
from argus.infrastructure.db import migration_support
from argus.infrastructure.db.base import Base
from argus.infrastructure.db.engine import async_url, connect_args
from argus.modules.registry import import_all_models

config = context.config
settings: Settings = config.attributes.get("settings") or load_settings()
import_all_models()
migration_support.configure(settings.database.app_role)
target_metadata = Base.metadata
_dsn = (settings.database.migration_url or settings.database.url).get_secret_value()


def _connect_args() -> dict[str, Any]:
    args = connect_args(settings.database, "argus-migrate")
    server_settings = dict(args["server_settings"])  # type: ignore[call-overload]
    server_settings["statement_timeout"] = "0"
    server_settings["lock_timeout"] = "10000"
    args["server_settings"] = server_settings
    return args


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        transaction_per_migration=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def _run_online() -> None:
    engine = create_async_engine(
        async_url(_dsn), poolclass=pool.NullPool, connect_args=_connect_args()
    )
    try:
        async with engine.connect() as connection:
            await connection.run_sync(_configure)
    finally:
        await engine.dispose()


def _run_offline() -> None:
    context.configure(
        url=async_url(_dsn).render_as_string(hide_password=True),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    _run_offline()
else:
    asyncio.run(_run_online())
