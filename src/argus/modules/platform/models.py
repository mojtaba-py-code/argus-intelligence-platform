"""Platform tables: organisation data exports."""

from __future__ import annotations

from datetime import datetime
from typing import Final
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKeyConstraint,
    Index,
    LargeBinary,
    String,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from argus.infrastructure.db.base import Base, CreatedAt, UUIDPrimaryKey, sql_in

EXPORT_STATUSES: Final = ("pending", "ready", "failed", "expired")


class OrganizationExport(Base, UUIDPrimaryKey, CreatedAt):
    """A complete, encrypted archive of an organisation's data, for its owners (portability,
    or before deleting the organisation). The archive lives in object storage under the same
    envelope encryption as documents and expires after ``platform.export_ttl_days``."""

    __tablename__ = "organization_exports"

    organization_id: Mapped[UUID]
    requested_by: Mapped[UUID]
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    storage_key: Mapped[str | None] = mapped_column(String(255))
    byte_size: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[bytes | None] = mapped_column(LargeBinary)
    documents_included: Mapped[bool | None]
    error_code: Mapped[str | None] = mapped_column(String(48))
    completed_at: Mapped[datetime | None]
    expires_at: Mapped[datetime]

    __table_args__ = (
        ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        CheckConstraint(f"status IN {sql_in(EXPORT_STATUSES)}", name="status"),
        Index("ix_organization_exports_org_created", "organization_id", "created_at"),
        # One export in preparation per organisation, even under concurrent requests.
        Index(
            "uq_organization_exports_one_pending",
            "organization_id",
            unique=True,
            postgresql_where=text("status = 'pending'"),
        ),
    )
