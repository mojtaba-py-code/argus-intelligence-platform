"""LLM accounting and prompt deployment tables."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Final
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    PrimaryKeyConstraint,
    SmallInteger,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column

from argus.infrastructure.db.base import Base, CreatedAt, UUIDPrimaryKey, sql_in

OUTCOMES: Final = (
    "ok",
    "refused",
    "error",
    "retryable_error",
    "invalid_output",
    "truncated",
    "blocked_policy",
    "blocked_budget",
    "circuit_open",
)


class LLMRequestRecord(Base, UUIDPrimaryKey, CreatedAt):
    """One row per provider attempt - including failures, which cost tokens too."""

    __tablename__ = "llm_requests"

    organization_id: Mapped[UUID]
    job_id: Mapped[UUID | None]
    """Provenance only (no foreign key): deleting a job must not erase what it cost."""
    agent_run_id: Mapped[UUID | None]
    task: Mapped[str] = mapped_column(String(64))
    prompt_name: Mapped[str] = mapped_column(String(64))
    prompt_version: Mapped[int] = mapped_column(Integer)
    prompt_sha256: Mapped[str] = mapped_column(String(64))
    provider: Mapped[str] = mapped_column(String(16))
    model: Mapped[str] = mapped_column(String(64))
    served_model: Mapped[str | None] = mapped_column(String(64))
    locality: Mapped[str] = mapped_column(String(16))
    classification: Mapped[int] = mapped_column(SmallInteger)
    outcome: Mapped[str] = mapped_column(String(24))
    error_code: Mapped[str | None] = mapped_column(String(48))
    input_tokens: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    output_tokens: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    cache_read_tokens: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    cache_write_tokens: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(14, 6), default=0, server_default="0")
    latency_ms: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    fallback_used: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    request_id: Mapped[str | None] = mapped_column(String(128))

    __table_args__ = (
        ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        CheckConstraint(f"outcome IN {sql_in(OUTCOMES)}", name="outcome"),
        CheckConstraint("cost_usd >= 0", name="cost"),
        Index("ix_llm_requests_org_created", "organization_id", "created_at"),
        Index("ix_llm_requests_job", "job_id"),
    )


class LLMUsageDaily(Base):
    """Daily roll-up per organisation and model: what budgets are checked against."""

    __tablename__ = "llm_usage_daily"

    organization_id: Mapped[UUID]
    day: Mapped[date]
    provider: Mapped[str] = mapped_column(String(16))
    model: Mapped[str] = mapped_column(String(64))
    requests: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    input_tokens: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    output_tokens: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(14, 6), default=0, server_default="0")

    __table_args__ = (
        PrimaryKeyConstraint("organization_id", "day", "provider", "model"),
        ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    )


class PromptDeployment(Base):
    """Which prompt version is active in which environment (platform configuration)."""

    __tablename__ = "prompt_deployments"

    name: Mapped[str] = mapped_column(String(64))
    environment: Mapped[str] = mapped_column(String(16))
    version: Mapped[int] = mapped_column(Integer)
    deployed_by: Mapped[str | None] = mapped_column(String(200))
    deployed_at: Mapped[datetime]

    __table_args__ = (
        PrimaryKeyConstraint("name", "environment"),
        CheckConstraint("version > 0", name="version"),
    )
