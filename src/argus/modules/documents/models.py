"""Uploaded documents and their lifecycle.

``pending_scan`` → (malware scan) → ``processing`` → (sandboxed parse) → ``ready``
                                  ↘ ``quarantined``                     ↘ ``failed``

Only ``processing``, ``ready`` and ``failed`` documents were scanned clean, so only those can be
downloaded; quarantined content is kept (encrypted) for investigation and is never parsed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Float,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from argus.infrastructure.db.base import Base, Timestamps, UUIDPrimaryKey, sql_in
from argus.security.parsing import KINDS

DOCUMENT_STATUSES = ("pending_scan", "processing", "ready", "failed", "quarantined")
DOWNLOADABLE = frozenset({"processing", "ready", "failed"})
RISK_LEVELS = ("none", "low", "medium", "high")


class Document(Base, UUIDPrimaryKey, Timestamps):
    __tablename__ = "documents"

    organization_id: Mapped[UUID]
    project_id: Mapped[UUID]
    filename: Mapped[str] = mapped_column(String(255))
    """Display name only (sanitised); storage keys never derive from it."""
    kind: Mapped[str] = mapped_column(String(16))
    media_type: Mapped[str] = mapped_column(String(100))
    byte_size: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[bytes] = mapped_column(LargeBinary)
    storage_key: Mapped[str] = mapped_column(String(255))
    classification: Mapped[int] = mapped_column(SmallInteger)
    status: Mapped[str] = mapped_column(
        String(16), default="pending_scan", server_default="pending_scan"
    )
    error_code: Mapped[str | None] = mapped_column(String(48))
    scan_engine: Mapped[str | None] = mapped_column(String(32))
    scan_signature: Mapped[str | None] = mapped_column(String(200))
    scanned_at: Mapped[datetime | None]
    title: Mapped[str | None] = mapped_column(String(300))
    author: Mapped[str | None] = mapped_column(String(200))
    language: Mapped[str | None] = mapped_column(String(35))
    page_count: Mapped[int | None] = mapped_column(Integer)
    text: Mapped[str | None] = mapped_column(Text)
    text_chars: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
    injection_score: Mapped[float] = mapped_column(Float, default=0.0, server_default="0")
    injection_level: Mapped[str] = mapped_column(String(8), default="none", server_default="none")
    injection_signals: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default="[]"
    )
    created_by: Mapped[UUID | None]
    processed_at: Mapped[datetime | None]

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("organization_id", "project_id", "sha256"),
        UniqueConstraint("organization_id", "id"),
        UniqueConstraint("storage_key"),
        CheckConstraint(f"status IN {sql_in(DOCUMENT_STATUSES)}", name="status"),
        CheckConstraint(f"kind IN {sql_in(KINDS)}", name="kind"),
        CheckConstraint(f"injection_level IN {sql_in(RISK_LEVELS)}", name="injection_level"),
        CheckConstraint("classification BETWEEN 0 AND 3", name="classification"),
        CheckConstraint("byte_size > 0", name="byte_size"),
        Index("ix_documents_project_created", "organization_id", "project_id", "created_at"),
    )
