"""Async engine and transactional units of work that carry the tenant context.

Every unit of work starts a transaction and immediately executes::

    SELECT set_config('argus.org_id', :org, true), set_config('argus.user_id', :user, true)

``is_local => true`` scopes the values to the transaction, so a pooled connection can never leak
one tenant's context into the next request, and the pattern stays correct behind PgBouncer in
transaction mode. Row-Level Security policies read these settings (see ADR 0002).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from uuid import UUID

import asyncpg
from sqlalchemy import text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from argus.core.config import DatabaseSettings
from argus.core.scope import TenantScope

_SET_CONTEXT = text(
    "SELECT set_config('argus.org_id', :org, true), set_config('argus.user_id', :usr, true)"
)
_TRANSACTION_MODES = {
    (False, True): text("SET TRANSACTION READ ONLY"),
    (True, False): text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"),
    (True, True): text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"),
}


def async_url(raw: str) -> URL:
    """Normalise a PostgreSQL DSN to the asyncpg driver."""
    url = make_url(raw)
    if url.get_backend_name() != "postgresql":
        msg = "only PostgreSQL DSNs are supported"
        raise ValueError(msg)
    return url.set(drivername="postgresql+asyncpg")


def connect_args(settings: DatabaseSettings, application_name: str) -> dict[str, object]:
    args: dict[str, object] = {
        "server_settings": {
            "application_name": application_name[:63],
            "statement_timeout": str(settings.statement_timeout_ms),
            "lock_timeout": str(settings.lock_timeout_ms),
            "idle_in_transaction_session_timeout": str(settings.idle_in_transaction_timeout_ms),
        },
    }
    if settings.tls_mode != "disable":
        args["ssl"] = settings.tls_mode
    else:
        args["ssl"] = False
    return args


class Database:
    """Owns the engine and session factory for one process."""

    def __init__(self, settings: DatabaseSettings, *, application_name: str = "argus") -> None:
        self._settings = settings
        self.engine: AsyncEngine = create_async_engine(
            async_url(settings.url.get_secret_value()),
            pool_size=settings.pool_size,
            max_overflow=settings.max_overflow,
            pool_timeout=settings.pool_timeout_s,
            pool_recycle=settings.pool_recycle_s,
            pool_pre_ping=True,
            echo=settings.echo,
            connect_args=connect_args(settings, application_name),
        )
        self._sessions = async_sessionmaker(
            self.engine, expire_on_commit=False, autoflush=True, class_=AsyncSession
        )

    @asynccontextmanager
    async def session(
        self,
        *,
        organization_id: UUID | None = None,
        user_id: UUID | None = None,
        read_only: bool = False,
        snapshot: bool = False,
    ) -> AsyncIterator[AsyncSession]:
        """One transaction. Commits when the block exits normally, rolls back on exception.

        ``snapshot`` runs it at REPEATABLE READ: every statement sees the same committed state,
        which multi-statement consistency checks (audit chain verification) depend on.
        """
        async with self._sessions() as session, session.begin():
            mode = _TRANSACTION_MODES.get((snapshot, read_only))
            if mode is not None:
                await session.execute(mode)
            await session.execute(
                _SET_CONTEXT,
                {
                    "org": str(organization_id) if organization_id else "",
                    "usr": str(user_id) if user_id else "",
                },
            )
            yield session

    def tenant(
        self, scope: TenantScope, *, read_only: bool = False, snapshot: bool = False
    ) -> AbstractAsyncContextManager[AsyncSession]:
        """Unit of work inside one organisation (RLS context = ``scope``)."""
        return self.session(
            organization_id=scope.organization_id,
            user_id=scope.actor.user_id,
            read_only=read_only,
            snapshot=snapshot,
        )

    async def connect_raw(self, application_name: str) -> asyncpg.Connection:
        """A dedicated asyncpg connection outside the pool (LISTEN/NOTIFY, leader locks)."""
        url = self.engine.url.set(drivername="postgresql")
        args = connect_args(self._settings, application_name)
        connection: asyncpg.Connection = await asyncpg.connect(
            url.render_as_string(hide_password=False),
            ssl=args["ssl"],
            server_settings=args["server_settings"],
        )
        return connection

    async def ping(self, timeout_s: float = 2.0) -> None:
        async with asyncio.timeout(timeout_s), self.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

    async def dispose(self) -> None:
        await self.engine.dispose()
