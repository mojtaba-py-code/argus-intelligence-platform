"""Audit integrity checks (tenant-scoped history for the security dashboard)."""

from __future__ import annotations

from datetime import datetime
from typing import Final
from uuid import UUID

from sqlalchemy import BigInteger, CheckConstraint, ForeignKeyConstraint, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from argus.infrastructure.db.base import Base, UUIDPrimaryKey, sql_in

TRIGGERS: Final = ("scheduled", "manual")
REASONS: Final = (
    "gap in sequence",
    "broken link",
    "hash mismatch",
    "chain head missing",
    "tail truncated",
    "rows beyond the chain head",
    "head mismatch",
    "checkpoint forged",
    "rows below the checkpoint",
)
"""Every reason :meth:`AuditService.verify_chain` can report (a fixed vocabulary)."""


class AuditVerification(Base, UUIDPrimaryKey):
    """One verification of an organisation's audit chain.

    No foreign key to the audit rows (they are append-only and outlive tenants); a cascade from
    ``organizations`` removes this history together with the tenant.
    """

    __tablename__ = "audit_verifications"

    organization_id: Mapped[UUID]
    verified_at: Mapped[datetime]
    trigger: Mapped[str] = mapped_column(String(16))
    valid: Mapped[bool]
    events: Mapped[int] = mapped_column(BigInteger)
    first_broken_seq: Mapped[int | None] = mapped_column(BigInteger)
    reason: Mapped[str | None] = mapped_column(String(64))
    duration_ms: Mapped[int] = mapped_column(Integer)
    requested_by: Mapped[UUID | None]
    """The user who asked for a manual check (``None`` for scheduled ones)."""

    __table_args__ = (
        ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        CheckConstraint(f"trigger IN {sql_in(TRIGGERS)}", name="trigger"),
        CheckConstraint("events >= 0 AND duration_ms >= 0", name="counts"),
        CheckConstraint(
            "(valid AND reason IS NULL AND first_broken_seq IS NULL) OR "
            "(NOT valid AND reason IS NOT NULL)",
            name="outcome",
        ),
        Index("ix_audit_verifications_org_time", "organization_id", "verified_at"),
    )
