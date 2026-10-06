"""Agent execution trail and kill switches."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any, Final
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from argus.infrastructure.db.base import Base, CreatedAt, Timestamps, UUIDPrimaryKey, sql_in

TERMINATIONS: Final = (
    "running",
    "completed",
    "max_iterations",
    "max_tool_calls",
    "budget",
    "timeout",
    "killed",
    "failed",
)
TOOL_OUTCOMES: Final = ("ok", "denied", "invalid_arguments", "killed", "error", "limit")
SWITCH_KINDS: Final = ("all", "agent", "tool", "provider", "model")


class AgentRun(Base, UUIDPrimaryKey, Timestamps):
    __tablename__ = "agent_runs"

    organization_id: Mapped[UUID]
    job_id: Mapped[UUID | None]
    agent: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="running", server_default="running")
    iterations: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    tool_calls: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(14, 6), default=0, server_default="0")
    finished_at: Mapped[datetime | None]
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")

    __table_args__ = (
        ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        UniqueConstraint("organization_id", "id"),
        CheckConstraint(f"status IN {sql_in(TERMINATIONS)}", name="status"),
        Index("ix_agent_runs_job", "organization_id", "job_id"),
        Index("ix_agent_runs_org_created", "organization_id", "created_at"),
    )


class ToolCallRecord(Base, UUIDPrimaryKey, CreatedAt):
    """Every tool request an agent made - denied ones included - with redacted arguments."""

    __tablename__ = "tool_calls"

    organization_id: Mapped[UUID]
    agent_run_id: Mapped[UUID]
    tool: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(24))
    arguments: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
    result: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
    latency_ms: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "agent_run_id"],
            ["agent_runs.organization_id", "agent_runs.id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(f"outcome IN {sql_in(TOOL_OUTCOMES)}", name="outcome"),
        Index("ix_tool_calls_run", "organization_id", "agent_run_id"),
        Index("ix_tool_calls_org_created", "organization_id", "created_at"),
    )


class KillSwitch(Base, UUIDPrimaryKey, Timestamps):
    """Stops an agent, a tool, a provider or a model - for one organisation or the platform."""

    __tablename__ = "kill_switches"

    organization_id: Mapped[UUID | None]
    """``None`` = platform-wide (set by operators); otherwise one organisation."""
    kind: Mapped[str] = mapped_column(String(16))
    target: Mapped[str] = mapped_column(String(64))
    """A name, or ``*`` for every target of that kind."""
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    reason: Mapped[str] = mapped_column(String(500))
    created_by: Mapped[str] = mapped_column(String(200))
    expires_at: Mapped[datetime | None]

    __table_args__ = (
        ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        CheckConstraint(f"kind IN {sql_in(SWITCH_KINDS)}", name="kind"),
        Index("ix_kill_switches_active", "kind", "target", postgresql_where="active"),
    )
