"""Source registry: where every piece of collected information came from (provenance)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    Float,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from argus.infrastructure.db.base import Base, CreatedAt, Timestamps, UUIDPrimaryKey, sql_in

SOURCE_STATUSES = ("pending", "fetched", "failed", "blocked")
TRUST_TIERS = ("high", "medium", "low", "unknown")
RISK_LEVELS = ("none", "low", "medium", "high")
DOMAIN_POLICIES = ("allow", "block", "require_approval")
DISCOVERY = ("manual", "search", "link", "monitor")


class Source(Base, UUIDPrimaryKey, Timestamps):
    __tablename__ = "sources"

    organization_id: Mapped[UUID]
    project_id: Mapped[UUID]
    url: Mapped[str] = mapped_column(Text)
    url_hash: Mapped[bytes] = mapped_column(LargeBinary)
    domain: Mapped[str] = mapped_column(String(253))
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    last_error_code: Mapped[str | None] = mapped_column(String(48))
    title: Mapped[str | None] = mapped_column(String(300))
    author: Mapped[str | None] = mapped_column(String(200))
    publisher: Mapped[str | None] = mapped_column(String(200))
    published_at: Mapped[datetime | None]
    language: Mapped[str | None] = mapped_column(String(16))
    reputation: Mapped[float] = mapped_column(Float, default=0.5, server_default="0.5")
    trust_tier: Mapped[str] = mapped_column(String(16), default="unknown", server_default="unknown")
    injection_level: Mapped[str] = mapped_column(String(8), default="none", server_default="none")
    injection_score: Mapped[float] = mapped_column(Float, default=0.0, server_default="0")
    discovered_via: Mapped[str] = mapped_column(
        String(16), default="manual", server_default="manual"
    )
    discovered_by_job_id: Mapped[UUID | None]
    search_query: Mapped[str | None] = mapped_column(String(500))
    created_by: Mapped[UUID | None]
    last_fetched_at: Mapped[datetime | None]
    fetch_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("organization_id", "project_id", "url_hash"),
        UniqueConstraint("organization_id", "id"),
        CheckConstraint(f"status IN {sql_in(SOURCE_STATUSES)}", name="status"),
        CheckConstraint(f"trust_tier IN {sql_in(TRUST_TIERS)}", name="trust_tier"),
        CheckConstraint(f"injection_level IN {sql_in(RISK_LEVELS)}", name="injection_level"),
        CheckConstraint(f"discovered_via IN {sql_in(DISCOVERY)}", name="discovered_via"),
        CheckConstraint("reputation BETWEEN 0 AND 1", name="reputation"),
        Index("ix_sources_project_created", "organization_id", "project_id", "created_at"),
        Index("ix_sources_domain", "organization_id", "domain"),
    )


class SourceSnapshot(Base, UUIDPrimaryKey, CreatedAt):
    """Content of a source at one point in time (deduplicated by content hash)."""

    __tablename__ = "source_snapshots"

    organization_id: Mapped[UUID]
    source_id: Mapped[UUID]
    fetched_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    final_url: Mapped[str] = mapped_column(Text)
    http_status: Mapped[int] = mapped_column(Integer)
    media_type: Mapped[str] = mapped_column(String(100))
    content_hash: Mapped[bytes] = mapped_column(LargeBinary)
    byte_size: Mapped[int] = mapped_column(Integer)
    server_ip: Mapped[str | None] = mapped_column(String(64))
    title: Mapped[str | None] = mapped_column(String(300))
    text: Mapped[str] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
    injection_score: Mapped[float] = mapped_column(Float, default=0.0, server_default="0")
    injection_level: Mapped[str] = mapped_column(String(8), default="none", server_default="none")
    injection_signals: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default="[]"
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "source_id"],
            ["sources.organization_id", "sources.id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("source_id", "content_hash"),
        UniqueConstraint("organization_id", "id"),
        CheckConstraint(f"injection_level IN {sql_in(RISK_LEVELS)}", name="injection_level"),
        Index("ix_source_snapshots_source_time", "organization_id", "source_id", "fetched_at"),
    )


class DomainPolicy(Base, UUIDPrimaryKey, Timestamps):
    __tablename__ = "domain_policies"

    organization_id: Mapped[UUID]
    domain: Mapped[str] = mapped_column(String(253))
    policy: Mapped[str] = mapped_column(String(24))
    reputation_override: Mapped[float | None] = mapped_column(Float)
    note: Mapped[str | None] = mapped_column(String(500))
    created_by: Mapped[UUID | None]

    __table_args__ = (
        ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        UniqueConstraint("organization_id", "domain"),
        CheckConstraint(f"policy IN {sql_in(DOMAIN_POLICIES)}", name="policy"),
        CheckConstraint(
            "reputation_override IS NULL OR reputation_override BETWEEN 0 AND 1", name="reputation"
        ),
    )
