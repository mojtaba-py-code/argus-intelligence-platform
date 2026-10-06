"""Monitors, their targets, and the changes they detect (tenant-scoped)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Float,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from argus.infrastructure.db.base import Base, CreatedAt, Timestamps, UUIDPrimaryKey, sql_in

MONITOR_STATUSES: Final = ("active", "paused")
MONITOR_KINDS: Final = ("urls", "search")
TOPICS: Final = (
    "product",
    "pricing",
    "website",
    "people",
    "jobs",
    "news",
    "funding",
    "technology",
)
CHANGE_STATUSES: Final = ("new", "acknowledged", "dismissed")
MIN_INTERVAL_MINUTES: Final = 60
MAX_INTERVAL_MINUTES: Final = 7 * 24 * 60


class Monitor(Base, UUIDPrimaryKey, Timestamps):
    """What to watch, how often, and when a change is worth an alert."""

    __tablename__ = "monitors"

    organization_id: Mapped[UUID]
    project_id: Mapped[UUID]
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(16))
    queries: Mapped[list[str]] = mapped_column(ARRAY(String(200)), default=list)
    """Search queries (``kind = 'search'``); URL targets live in ``monitor_targets``."""
    topics: Mapped[list[str]] = mapped_column(ARRAY(String(16)), default=list)
    interval_minutes: Mapped[int] = mapped_column(Integer)
    significance_threshold: Mapped[float] = mapped_column(Float, default=0.5)
    notify_email: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    next_run_at: Mapped[datetime]
    last_run_at: Mapped[datetime | None]
    last_error_code: Mapped[str | None] = mapped_column(String(48))
    created_by_user_id: Mapped[UUID | None]
    created_by_api_key_id: Mapped[UUID | None]

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("organization_id", "id"),
        CheckConstraint(f"kind IN {sql_in(MONITOR_KINDS)}", name="kind"),
        CheckConstraint(f"status IN {sql_in(MONITOR_STATUSES)}", name="status"),
        CheckConstraint(
            f"interval_minutes BETWEEN {MIN_INTERVAL_MINUTES} AND {MAX_INTERVAL_MINUTES}",
            name="interval",
        ),
        CheckConstraint("significance_threshold BETWEEN 0 AND 1", name="threshold"),
        Index("ix_monitors_project", "organization_id", "project_id", "created_at"),
        Index("ix_monitors_due", "next_run_at", postgresql_where=text("status = 'active'")),
    )


class MonitorTarget(Base, UUIDPrimaryKey, Timestamps):
    """One watched URL and the snapshot it was last compared against.

    The monitor keeps its own pointer instead of relying on "new snapshot" flags: content that
    returns to an earlier version (A → B → A) reuses an old snapshot row but is still a change.
    """

    __tablename__ = "monitor_targets"

    organization_id: Mapped[UUID]
    monitor_id: Mapped[UUID]
    url: Mapped[str] = mapped_column(Text)
    source_id: Mapped[UUID | None]
    last_snapshot_id: Mapped[UUID | None]
    last_checked_at: Mapped[datetime | None]
    last_status: Mapped[str | None] = mapped_column(String(16))
    last_error_code: Mapped[str | None] = mapped_column(String(48))
    discovered: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    """Found by a search monitor (bounded and replaceable) rather than chosen by a person."""

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitors.organization_id", "monitors.id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("monitor_id", "url"),
        UniqueConstraint("organization_id", "id"),
        Index("ix_monitor_targets_monitor", "organization_id", "monitor_id"),
    )


class MonitorChange(Base, UUIDPrimaryKey, CreatedAt):
    """A meaningful difference between two snapshots of a target."""

    __tablename__ = "monitor_changes"

    organization_id: Mapped[UUID]
    monitor_id: Mapped[UUID]
    target_id: Mapped[UUID]
    previous_snapshot_id: Mapped[UUID | None]
    snapshot_id: Mapped[UUID]
    topics: Mapped[list[str]] = mapped_column(ARRAY(String(16)), default=list)
    significance: Mapped[float] = mapped_column(Float)
    summary: Mapped[str] = mapped_column(String(600))
    diff: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    """Bounded excerpts of added and removed lines (untrusted text, sanitised)."""
    alerted: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    status: Mapped[str] = mapped_column(String(16), default="new", server_default="new")
    agent_run_id: Mapped[UUID | None]

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "monitor_id"],
            ["monitors.organization_id", "monitors.id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["organization_id", "target_id"],
            ["monitor_targets.organization_id", "monitor_targets.id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(f"status IN {sql_in(CHANGE_STATUSES)}", name="status"),
        CheckConstraint("significance BETWEEN 0 AND 1", name="significance"),
        Index("ix_monitor_changes_monitor", "organization_id", "monitor_id", "created_at"),
    )
