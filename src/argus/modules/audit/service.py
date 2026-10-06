"""Tamper-evident audit logging.

Each organisation has its own chain (``chain_key = <organization id>``); events without an
organisation (logins, registrations) go to the ``platform`` chain. Appending an event:

1. lock the chain head row (``SELECT ... FOR UPDATE``) - serialises appends per chain only;
2. ``hash = HMAC-SHA256(key, prev_hash || canonical_json(event))``;
3. insert the event (plain ``INSERT`` without ``RETURNING``: under RLS a returned row must also
   be readable, which platform events are not), then advance the head.

Verification recomputes the chain from the genesis hash, checks sequence continuity from 1 and
compares the tail with the head row, so edits, deletions (first, middle or last rows),
re-orderings and truncations are all detected.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import func, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.clock import Clock
from argus.core.crypto import constant_time_equals, hmac_sha256
from argus.core.logging import get_logger
from argus.core.redaction import redact
from argus.core.scope import Actor, TenantScope
from argus.infrastructure.db import Database
from argus.modules.audit.models import AuditChainHead, AuditCheckpoint, AuditLog
from argus.security.principals import ClientInfo

log = get_logger(__name__)
GENESIS_HASH = b"\x00" * 32
PLATFORM_CHAIN = "platform"
_MAX_DETAIL_CHARS = 8_000


class AuditCategory(StrEnum):
    AUTHENTICATION = "authentication"
    ACCOUNT = "account"
    AUTHORIZATION = "authorization"
    ORGANIZATION = "organization"
    DATA_ACCESS = "data_access"
    CONFIGURATION = "configuration"
    RESEARCH = "research"
    AGENT = "agent"
    ADMINISTRATION = "administration"
    SECURITY = "security"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


SECURITY_CATEGORIES = (
    AuditCategory.AUTHENTICATION,
    AuditCategory.AUTHORIZATION,
    AuditCategory.SECURITY,
)


@dataclass(frozen=True)
class AuditEvent:
    action: str
    category: AuditCategory
    actor: Actor
    outcome: AuditOutcome = AuditOutcome.SUCCESS
    organization_id: UUID | None = None
    target_type: str | None = None
    target_id: str | None = None
    client: ClientInfo | None = None
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ChainVerification:
    chain_key: str
    events: int
    """Events verified (after the newest checkpoint, when the chain has been pruned)."""
    valid: bool
    first_broken_seq: int | None = None
    reason: str | None = None


@dataclass(frozen=True)
class PruneResult:
    pruned: int
    through_seq: int | None = None
    refused: str | None = None


def _canonical_details(details: Mapping[str, Any]) -> dict[str, Any]:
    """Redact, make JSON-safe and bound the size - the same object is hashed and stored."""
    safe: dict[str, Any] = json.loads(json.dumps(redact(dict(details)), default=str))
    if len(json.dumps(safe)) > _MAX_DETAIL_CHARS:
        return {"truncated": True}
    return safe


def _canonical(row: Mapping[str, Any]) -> bytes:
    def encode(value: Any) -> Any:
        if isinstance(value, datetime):
            return value.astimezone(UTC).isoformat()
        if isinstance(value, UUID):
            return str(value)
        return value

    payload = {key: encode(value) for key, value in row.items()}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


_HASHED_FIELDS = (
    "chain_key",
    "chain_seq",
    "organization_id",
    "occurred_at",
    "action",
    "category",
    "outcome",
    "actor_type",
    "actor_id",
    "user_id",
    "target_type",
    "target_id",
    "request_id",
    "ip_address",
    "user_agent",
    "details",
)


_INSERT_EVENT = text(
    "INSERT INTO audit_logs (chain_key, chain_seq, organization_id, occurred_at, action, "
    "category, outcome, actor_type, actor_id, user_id, target_type, target_id, request_id, "
    "ip_address, user_agent, details, prev_hash, hash) VALUES (:chain_key, :chain_seq, "
    ":organization_id, :occurred_at, :action, :category, :outcome, :actor_type, :actor_id, "
    ":user_id, :target_type, :target_id, :request_id, :ip_address, :user_agent, "
    "CAST(:details AS jsonb), :prev_hash, :hash)"
)


class AuditService:
    def __init__(self, *, hmac_key: bytes, clock: Clock, database: Database) -> None:
        self._key = hmac_key
        self._clock = clock
        self._database = database

    def _hash(self, prev_hash: bytes, row: Mapping[str, Any]) -> bytes:
        return hmac_sha256(self._key, prev_hash, _canonical({k: row[k] for k in _HASHED_FIELDS}))

    def checkpoint_mac(self, chain_key: str, seq: int, chain_hash: bytes) -> bytes:
        return hmac_sha256(
            self._key,
            b"argus-audit-checkpoint",
            _canonical({"chain_key": chain_key, "seq": seq, "hash": chain_hash.hex()}),
        )

    async def record(self, session: AsyncSession, event: AuditEvent) -> None:
        """Append inside the caller's transaction (atomic with the audited change)."""
        chain_key = str(event.organization_id) if event.organization_id else PLATFORM_CHAIN
        await session.execute(
            text(
                "INSERT INTO audit_chain_heads (chain_key, last_seq, last_hash) "
                "VALUES (:k, 0, :h) ON CONFLICT (chain_key) DO NOTHING"
            ),
            {"k": chain_key, "h": GENESIS_HASH},
        )
        head = (
            await session.execute(
                select(AuditChainHead.last_seq, AuditChainHead.last_hash)
                .where(AuditChainHead.chain_key == chain_key)
                .with_for_update()
            )
        ).one()
        client = event.client or ClientInfo()
        row: dict[str, Any] = {
            "chain_key": chain_key,
            "chain_seq": head.last_seq + 1,
            "organization_id": event.organization_id,
            "occurred_at": self._clock.now().astimezone(UTC),
            "action": event.action[:64],
            "category": event.category.value,
            "outcome": event.outcome.value,
            "actor_type": event.actor.type.value,
            "actor_id": event.actor.id,
            "user_id": event.actor.user_id,
            "target_type": event.target_type,
            "target_id": event.target_id[:64] if event.target_id else None,
            "request_id": client.request_id[:128] if client.request_id else None,
            "ip_address": client.ip_address[:64] if client.ip_address else None,
            "user_agent": client.user_agent[:256] if client.user_agent else None,
            "details": _canonical_details(event.details),
        }
        digest = self._hash(bytes(head.last_hash), row)
        # Plain INSERT: no RETURNING (RLS hides platform rows from the runtime role) and no
        # key prefetch (the id is GENERATED ALWAYS by PostgreSQL).
        await session.execute(
            _INSERT_EVENT,
            {
                **row,
                "details": json.dumps(row["details"], ensure_ascii=False),
                "prev_hash": bytes(head.last_hash),
                "hash": digest,
            },
        )
        await session.execute(
            update(AuditChainHead)
            .where(AuditChainHead.chain_key == chain_key)
            .values(last_seq=row["chain_seq"], last_hash=digest)
        )

    async def record_detached(self, event: AuditEvent) -> None:
        """Append in a separate transaction - for failures that must be recorded even though the
        request's own transaction rolls back (failed logins, denied access)."""
        try:
            async with self._database.session(
                organization_id=event.organization_id, user_id=event.actor.user_id
            ) as session:
                await self.record(session, event)
        except Exception as exc:  # noqa: BLE001  # pragma: no cover - must not mask the real error
            log.error("audit.record_failed", action=event.action, error_type=type(exc).__name__)

    async def verify_chain(
        self, session: AsyncSession, chain_key: str, *, batch_size: int = 1_000
    ) -> ChainVerification:
        """Recompute one chain from its genesis and compare the tail with the head row.

        Call it inside a snapshot transaction (``Database.session(snapshot=True)``): the head and
        every row then come from one consistent view, so an append that commits halfway through
        cannot look like tampering. Rows are streamed in keyset pages of ``batch_size`` and read
        as plain rows (not ORM objects), so memory stays flat however long the chain is.

        Detected: edited rows (hash mismatch), re-linked rows (broken link), deleted rows -
        including the first ones (gap in sequence) - deleted tail rows (tail truncated), rows
        appended without advancing the head, a rewritten head, a forged checkpoint, and rows
        slipped in below a checkpoint. A pruned chain is verified from its newest checkpoint
        (whose MAC must verify) instead of genesis.
        """
        head = (
            await session.execute(
                select(AuditChainHead.last_seq, AuditChainHead.last_hash).where(
                    AuditChainHead.chain_key == chain_key
                )
            )
        ).one_or_none()
        checkpoint = (
            await session.execute(
                select(AuditCheckpoint.seq, AuditCheckpoint.hash, AuditCheckpoint.mac)
                .where(AuditCheckpoint.chain_key == chain_key)
                .order_by(AuditCheckpoint.seq.desc())
                .limit(1)
            )
        ).one_or_none()
        table = AuditLog.__table__
        columns = [table.c[name] for name in (*_HASHED_FIELDS, "prev_hash", "hash")]
        prev_hash = GENESIS_HASH
        expected = 1
        if checkpoint is not None:
            signed = self.checkpoint_mac(chain_key, checkpoint.seq, bytes(checkpoint.hash))
            if not constant_time_equals(signed, bytes(checkpoint.mac)):
                return ChainVerification(chain_key, 0, False, checkpoint.seq, "checkpoint forged")
            # Pruning removed everything up to the checkpoint and the database refuses new rows
            # down there, so any row below it was put there around both.
            below = (
                await session.execute(
                    select(func.min(table.c.chain_seq)).where(
                        table.c.chain_key == chain_key, table.c.chain_seq <= checkpoint.seq
                    )
                )
            ).scalar_one()
            if below is not None:
                return ChainVerification(chain_key, 0, False, below, "rows below the checkpoint")
            prev_hash, expected = bytes(checkpoint.hash), checkpoint.seq + 1
        first = expected
        while True:
            rows = (
                await session.execute(
                    select(*columns)
                    .where(table.c.chain_key == chain_key, table.c.chain_seq >= expected)
                    .order_by(table.c.chain_seq)
                    .limit(batch_size)
                )
            ).all()
            if not rows:
                break
            for row in rows:
                verified = expected - first
                if row.chain_seq != expected:
                    return ChainVerification(
                        chain_key, verified, False, expected, "gap in sequence"
                    )
                if not constant_time_equals(bytes(row.prev_hash), prev_hash):
                    return ChainVerification(chain_key, verified, False, expected, "broken link")
                values = {name: row._mapping[name] for name in _HASHED_FIELDS}
                if not constant_time_equals(self._hash(prev_hash, values), bytes(row.hash)):
                    return ChainVerification(chain_key, verified, False, expected, "hash mismatch")
                prev_hash = bytes(row.hash)
                expected += 1
        last = expected - 1
        events = expected - first
        if head is None:
            if last == 0:
                return ChainVerification(chain_key, 0, True)
            return ChainVerification(chain_key, events, False, first, "chain head missing")
        if last < head.last_seq:
            return ChainVerification(chain_key, events, False, last + 1, "tail truncated")
        if last > head.last_seq:
            return ChainVerification(
                chain_key, events, False, head.last_seq + 1, "rows beyond the chain head"
            )
        if last and not constant_time_equals(prev_hash, bytes(head.last_hash)):
            return ChainVerification(chain_key, events, False, last, "head mismatch")
        return ChainVerification(chain_key, events, True)

    async def prune(
        self,
        chain_key: str,
        *,
        older_than: datetime,
        organization_id: UUID | None,
        database: Database | None = None,
    ) -> PruneResult:
        """Delete events older than ``older_than`` behind a signed checkpoint (retention).

        Refused when the chain does not verify - pruning must never destroy the evidence of
        tampering. The database function re-checks that the checkpoint matches the stored chain,
        that an organisation context only prunes its own chain, and that nothing younger than 90
        days is ever removed, whatever the caller asks. ``database`` is the owner-role database
        for the platform chain (the runtime role cannot read it)."""
        db = database or self._database
        async with db.session(
            organization_id=organization_id, read_only=True, snapshot=True
        ) as session:
            result = await self.verify_chain(session, chain_key)
            if not result.valid:
                return PruneResult(0, refused="the chain does not verify")
            organization_filter = (
                AuditLog.organization_id.is_(None)
                if organization_id is None
                else AuditLog.organization_id == organization_id
            )
            row = (
                await session.execute(
                    select(AuditLog.chain_seq, AuditLog.hash)
                    .where(
                        organization_filter,
                        AuditLog.chain_key == chain_key,
                        AuditLog.occurred_at < older_than,
                    )
                    .order_by(AuditLog.occurred_at.desc())
                    .limit(1)
                )
            ).one_or_none()
        if row is None:
            return PruneResult(0)
        async with db.session(organization_id=organization_id) as session:
            pruned = (
                await session.execute(
                    text("SELECT argus_prune_audit(:chain, :seq, :hash, :mac)"),
                    {
                        "chain": chain_key,
                        "seq": row.chain_seq,
                        "hash": bytes(row.hash),
                        "mac": self.checkpoint_mac(chain_key, row.chain_seq, bytes(row.hash)),
                    },
                )
            ).scalar_one()
            await self.record(
                session,
                AuditEvent(
                    action="audit.pruned",
                    category=AuditCategory.SECURITY,
                    actor=Actor.system(),
                    organization_id=organization_id,
                    target_type="audit_chain",
                    target_id=chain_key,
                    details={"through_seq": row.chain_seq, "rows": int(pruned)},
                ),
            )
        return PruneResult(int(pruned), row.chain_seq)

    async def chain_keys(self, session: AsyncSession) -> list[str]:
        return list((await session.execute(select(AuditChainHead.chain_key))).scalars().all())

    async def checkpoint(self, session: AsyncSession, chain_key: str) -> dict[str, Any] | None:
        """The newest checkpoint of a pruned chain - where its verification starts - in the
        form evidence copies carry it, so they stay verifiable offline with the audit key."""
        row = (
            await session.execute(
                select(
                    AuditCheckpoint.seq,
                    AuditCheckpoint.hash,
                    AuditCheckpoint.mac,
                    AuditCheckpoint.created_at,
                )
                .where(AuditCheckpoint.chain_key == chain_key)
                .order_by(AuditCheckpoint.seq.desc())
                .limit(1)
            )
        ).one_or_none()
        if row is None:
            return None
        return {
            "chain_key": chain_key,
            "seq": row.seq,
            "hash": bytes(row.hash).hex(),
            "mac": bytes(row.mac).hex(),
            "created_at": row.created_at.isoformat(),
        }

    async def list_for_organization(
        self,
        scope: TenantScope,
        *,
        limit: int,
        before_id: int | None = None,
        action_prefix: str | None = None,
        security_only: bool = False,
    ) -> list[AuditLog]:
        """Newest first; ``before_id`` is the keyset cursor. RLS restricts rows to the tenant.

        ``security_only`` keeps what a security review looks at first: denied and failed
        actions, and every authentication, authorisation or security event.
        """
        stmt = select(AuditLog).where(AuditLog.organization_id == scope.organization_id)
        if security_only:
            stmt = stmt.where(
                or_(
                    AuditLog.outcome.in_((AuditOutcome.DENIED, AuditOutcome.FAILURE)),
                    AuditLog.category.in_(SECURITY_CATEGORIES),
                )
            )
        if before_id is not None:
            stmt = stmt.where(AuditLog.id < before_id)
        if action_prefix:
            escaped = action_prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            stmt = stmt.where(AuditLog.action.like(f"{escaped}%", escape="\\"))
        stmt = stmt.order_by(AuditLog.id.desc()).limit(limit)
        async with self._database.tenant(scope, read_only=True) as session:
            return list((await session.execute(stmt)).scalars().all())
