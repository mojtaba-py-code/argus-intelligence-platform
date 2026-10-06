"""``Idempotency-Key`` support (IETF draft "The Idempotency-Key HTTP Header Field").

The record is written **in the same transaction** as the side effect it protects, so:

* a retried request after success replays the stored response (no second research job);
* a concurrent duplicate blocks on the unique key until the first transaction finishes, then
  replays its response;
* if the first transaction rolled back, the key was never stored - the retry runs normally;
* the same key with a *different* body is rejected (422) instead of silently returning a response
  for a request the client did not send.

Keys are scoped per principal and expire after 24 hours (swept by the scheduler).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Index, Integer, LargeBinary, PrimaryKeyConstraint, String, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from argus.core.crypto import sha256
from argus.core.errors import ValidationFailed
from argus.infrastructure.db import Database
from argus.infrastructure.db.base import Base, CreatedAt

KEY_PATTERN = re.compile(r"^[A-Za-z0-9_.:\-]{8,128}$")
TTL_HOURS = 24


class IdempotencyRecord(Base, CreatedAt):
    __tablename__ = "idempotency_keys"

    principal_key: Mapped[str] = mapped_column(String(80))
    key: Mapped[str] = mapped_column(String(128))
    request_hash: Mapped[bytes] = mapped_column(LargeBinary)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_body: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    resource_id: Mapped[UUID | None]
    expires_at: Mapped[datetime]

    __table_args__ = (
        PrimaryKeyConstraint("principal_key", "key"),
        Index("ix_idempotency_keys_expires", "expires_at"),
    )


@dataclass(frozen=True)
class Replay:
    status: int
    body: dict[str, Any]


def request_fingerprint(method: str, path: str, body: Any) -> bytes:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(f"{method.upper()} {path}\n{canonical}")


def validate_key(key: str) -> str:
    if not KEY_PATTERN.fullmatch(key):
        msg = "Idempotency-Key must be 8-128 characters of letters, digits and _ . : -"
        raise ValidationFailed(msg)
    return key


_CLAIM = text(
    """
    INSERT INTO idempotency_keys (principal_key, key, request_hash, expires_at, created_at)
    VALUES (:principal, :key, :hash, now() + make_interval(hours => :ttl), now())
    ON CONFLICT (principal_key, key) DO NOTHING
    RETURNING key
    """
)
_EXISTING = text(
    "SELECT request_hash, response_status, response_body, expires_at > now() AS live "
    "FROM idempotency_keys WHERE principal_key = :principal AND key = :key FOR UPDATE"
)


class Idempotency:
    async def begin(
        self, session: AsyncSession, *, principal_key: str, key: str, fingerprint: bytes
    ) -> Replay | None:
        """Reserve the key in the current transaction; return a stored response to replay."""
        params = {"principal": principal_key, "key": validate_key(key)}
        claimed = (
            await session.execute(_CLAIM, {**params, "hash": fingerprint, "ttl": TTL_HOURS})
        ).scalar_one_or_none()
        if claimed is not None:
            return None
        row = (await session.execute(_EXISTING, params)).one()
        if not row.live:
            await session.execute(
                text(
                    "UPDATE idempotency_keys SET request_hash = :hash, response_status = NULL, "
                    "response_body = NULL, resource_id = NULL, created_at = now(), "
                    "expires_at = now() + make_interval(hours => :ttl) "
                    "WHERE principal_key = :principal AND key = :key"
                ),
                {**params, "hash": fingerprint, "ttl": TTL_HOURS},
            )
            return None
        if bytes(row.request_hash) != fingerprint:
            raise ValidationFailed(
                "This Idempotency-Key was already used with a different request."
            )
        if row.response_status is None:  # pragma: no cover - same-transaction reuse only
            raise ValidationFailed("A request with this Idempotency-Key is still in progress.")
        return Replay(int(row.response_status), dict(row.response_body or {}))

    async def complete(
        self,
        session: AsyncSession,
        *,
        principal_key: str,
        key: str,
        status: int,
        body: dict[str, Any],
        resource_id: UUID | None = None,
    ) -> None:
        await session.execute(
            text(
                "UPDATE idempotency_keys SET response_status = :status, "
                "response_body = CAST(:body AS jsonb), resource_id = :rid "
                "WHERE principal_key = :principal AND key = :key"
            ),
            {
                "status": status,
                "body": json.dumps(body, default=str),
                "rid": resource_id,
                "principal": principal_key,
                "key": key,
            },
        )

    async def sweep(self, database: Database) -> int:
        async with database.session() as session:
            result = await session.execute(
                text("DELETE FROM idempotency_keys WHERE expires_at < now()")
            )
            return int(result.rowcount)  # type: ignore[attr-defined]
