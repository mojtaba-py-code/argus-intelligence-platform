"""The ``jobs`` table. Not tenant-RLS-protected: it is infrastructure and carries identifiers
only (payloads reference rows; they never contain document text, prompts or secrets)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, SmallInteger, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from argus.infrastructure.db.base import Base, Timestamps, UUIDPrimaryKey, sql_in

JOB_STATUSES = ("queued", "running", "succeeded", "failed", "dead", "cancelled")


class Job(Base, UUIDPrimaryKey, Timestamps):
    __tablename__ = "jobs"

    queue: Mapped[str] = mapped_column(String(32))
    task: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    status: Mapped[str] = mapped_column(String(16), default="queued", server_default="queued")
    priority: Mapped[int] = mapped_column(SmallInteger, default=0, server_default="0")
    run_at: Mapped[datetime]
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    max_attempts: Mapped[int] = mapped_column(Integer)
    timeout_s: Mapped[int] = mapped_column(Integer)
    locked_by: Mapped[str | None] = mapped_column(String(128))
    locked_until: Mapped[datetime | None]
    last_error: Mapped[str | None] = mapped_column(Text)
    dedup_key: Mapped[str | None] = mapped_column(String(200))
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    trace_parent: Mapped[str | None] = mapped_column(String(55))
    """W3C ``traceparent`` of the span that enqueued the job: the worker continues that trace."""

    __table_args__ = (
        CheckConstraint(f"status IN {sql_in(JOB_STATUSES)}", name="status"),
        CheckConstraint("max_attempts BETWEEN 1 AND 50", name="max_attempts"),
        CheckConstraint("timeout_s BETWEEN 1 AND 86400", name="timeout"),
        CheckConstraint(
            "trace_parent ~ '^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$'",
            name="trace_parent",
        ),
        Index(
            "ix_jobs_claim",
            "queue",
            text("priority DESC"),
            "run_at",
            postgresql_where=text("status = 'queued'"),
        ),
        Index("ix_jobs_leases", "locked_until", postgresql_where=text("status = 'running'")),
        Index(
            "uq_jobs_active_dedup",
            "dedup_key",
            unique=True,
            postgresql_where=text("dedup_key IS NOT NULL AND status IN ('queued', 'running')"),
        ),
        Index("ix_jobs_organization", "organization_id"),
    )
