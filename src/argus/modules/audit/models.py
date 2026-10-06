"""Audit tables.

``audit_logs`` is append-only three times over: the runtime role has no UPDATE/DELETE grant, a
trigger rejects modification even for other roles, and every row carries an HMAC chain hash
(key outside the database), so tampering by someone with raw database access is *detectable*.
There is deliberately no foreign key to ``organizations``: audit history must outlive the tenant.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Identity,
    Index,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from argus.infrastructure.db.base import Base, sql_in

OUTCOMES = ("success", "failure", "denied")
CATEGORIES = (
    "authentication",
    "account",
    "authorization",
    "organization",
    "data_access",
    "configuration",
    "research",
    "agent",
    "administration",
    "security",
)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    chain_key: Mapped[str] = mapped_column(String(64))
    chain_seq: Mapped[int] = mapped_column(BigInteger)
    organization_id: Mapped[UUID | None]
    occurred_at: Mapped[datetime]
    action: Mapped[str] = mapped_column(String(64))
    category: Mapped[str] = mapped_column(String(32))
    outcome: Mapped[str] = mapped_column(String(16))
    actor_type: Mapped[str] = mapped_column(String(24))
    actor_id: Mapped[UUID | None]
    user_id: Mapped[UUID | None]
    target_type: Mapped[str | None] = mapped_column(String(48))
    target_id: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(128))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(256))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB)
    prev_hash: Mapped[bytes] = mapped_column(LargeBinary)
    hash: Mapped[bytes] = mapped_column(LargeBinary)

    __table_args__ = (
        UniqueConstraint("chain_key", "chain_seq"),
        Index("ix_audit_logs_org_time", "organization_id", "occurred_at"),
        Index("ix_audit_logs_user_time", "user_id", "occurred_at"),
        CheckConstraint(f"outcome IN {sql_in(OUTCOMES)}", name="outcome"),
        CheckConstraint(f"category IN {sql_in(CATEGORIES)}", name="category"),
        # Never `INSERT ... RETURNING`: PostgreSQL applies the SELECT policy to returned rows,
        # and platform events (organization_id IS NULL) are deliberately not readable by the
        # runtime role.
        {"implicit_returning": False},
    )


class AuditChainHead(Base):
    __tablename__ = "audit_chain_heads"

    chain_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_seq: Mapped[int] = mapped_column(BigInteger)
    last_hash: Mapped[bytes] = mapped_column(LargeBinary)


class AuditCheckpoint(Base):
    """Where a pruned chain now starts: the last pruned event's sequence number and hash, signed
    with the audit HMAC key. Verification resumes from the newest checkpoint, so retention can
    delete old events without weakening the chain - a forged checkpoint fails its MAC. Written
    only by ``argus_prune_audit()`` (the runtime role can read, never write)."""

    __tablename__ = "audit_checkpoints"

    chain_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    hash: Mapped[bytes] = mapped_column(LargeBinary)
    mac: Mapped[bytes] = mapped_column(LargeBinary)
    pruned_rows: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
