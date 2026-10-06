"""Research jobs, plans, checkpointed steps, approvals, findings and citations (tenant-scoped)."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from argus.infrastructure.db.base import Base, CreatedAt, Timestamps, UUIDPrimaryKey, sql_in

JOB_STATUSES = (
    "queued",
    "running",
    "awaiting_approval",
    "completed",
    "failed",
    "cancelled",
)
TERMINAL = frozenset({"completed", "failed", "cancelled"})
MODES = ("web", "documents", "hybrid")
STEP_STATUSES = ("pending", "running", "succeeded", "failed", "skipped")
APPROVAL_STATUSES = ("pending", "approved", "rejected", "expired")
FINDING_KINDS = ("fact", "inference", "hypothesis", "opinion")
SUPPORT_LEVELS = ("unverified", "supported", "partial", "unsupported", "contradicted")
CONTRADICTION_EXPLANATIONS = (
    "different_time_periods",
    "different_scope_or_definition",
    "source_reliability",
    "measurement_or_estimate",
    "unresolved",
)
PREFERENCES = ("a", "b", "neither")


class ResearchJob(Base, UUIDPrimaryKey, Timestamps):
    __tablename__ = "research_jobs"

    organization_id: Mapped[UUID]
    project_id: Mapped[UUID]
    created_by_user_id: Mapped[UUID | None]
    created_by_api_key_id: Mapped[UUID | None]
    title: Mapped[str] = mapped_column(String(200))
    objective: Mapped[str] = mapped_column(Text)
    mode: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(24), default="queued", server_default="queued")
    stage: Mapped[str | None] = mapped_column(String(32))
    progress: Mapped[int] = mapped_column(SmallInteger, default=0, server_default="0")
    budget_usd: Mapped[Decimal] = mapped_column(Numeric(12, 4))
    spent_usd: Mapped[Decimal] = mapped_column(
        Numeric(14, 6), default=Decimal(0), server_default="0"
    )
    input_tokens: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    output_tokens: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    max_sources: Mapped[int] = mapped_column(Integer)
    options: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
    queue_job_id: Mapped[UUID | None]
    error_code: Mapped[str | None] = mapped_column(String(48))
    error_message: Mapped[str | None] = mapped_column(String(500))
    cancel_requested_at: Mapped[datetime | None]
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("organization_id", "id"),
        CheckConstraint(f"status IN {sql_in(JOB_STATUSES)}", name="status"),
        CheckConstraint(f"mode IN {sql_in(MODES)}", name="mode"),
        CheckConstraint("progress BETWEEN 0 AND 100", name="progress"),
        CheckConstraint("budget_usd > 0", name="budget_positive"),
        Index("ix_research_jobs_project_created", "organization_id", "project_id", "created_at"),
        Index(
            "ix_research_jobs_active",
            "organization_id",
            "status",
            postgresql_where=text("status IN ('queued', 'running', 'awaiting_approval')"),
        ),
    )


class ResearchPlan(Base, UUIDPrimaryKey, CreatedAt):
    __tablename__ = "research_plans"

    organization_id: Mapped[UUID]
    job_id: Mapped[UUID]
    version: Mapped[int] = mapped_column(Integer)
    plan: Mapped[dict[str, Any]] = mapped_column(JSONB)
    model: Mapped[str | None] = mapped_column(String(80))
    prompt_version: Mapped[str | None] = mapped_column(String(80))

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "job_id"],
            ["research_jobs.organization_id", "research_jobs.id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("job_id", "version"),
    )


class ResearchStep(Base, UUIDPrimaryKey, Timestamps):
    __tablename__ = "research_steps"

    organization_id: Mapped[UUID]
    job_id: Mapped[UUID]
    key: Mapped[str] = mapped_column(String(48))
    position: Mapped[int] = mapped_column(SmallInteger)
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    output: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
    error_code: Mapped[str | None] = mapped_column(String(48))
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "job_id"],
            ["research_jobs.organization_id", "research_jobs.id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("job_id", "key"),
        CheckConstraint(f"status IN {sql_in(STEP_STATUSES)}", name="status"),
    )


class ApprovalRequest(Base, UUIDPrimaryKey, CreatedAt):
    __tablename__ = "approval_requests"

    organization_id: Mapped[UUID]
    project_id: Mapped[UUID]
    job_id: Mapped[UUID]
    kind: Mapped[str] = mapped_column(String(48))
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    reason: Mapped[str] = mapped_column(String(500))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
    expires_at: Mapped[datetime]
    decided_by: Mapped[UUID | None]
    decided_at: Mapped[datetime | None]
    decision_note: Mapped[str | None] = mapped_column(String(500))

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "job_id"],
            ["research_jobs.organization_id", "research_jobs.id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(f"status IN {sql_in(APPROVAL_STATUSES)}", name="status"),
        Index("ix_approval_requests_pending", "organization_id", "status", "created_at"),
    )


class ResearchFinding(Base, UUIDPrimaryKey, CreatedAt):
    """A claim an analyst made for one sub-question, with its mechanical verification result."""

    __tablename__ = "research_findings"

    organization_id: Mapped[UUID]
    job_id: Mapped[UUID]
    question_id: Mapped[str] = mapped_column(String(8))
    ordinal: Mapped[int] = mapped_column(Integer)
    statement: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float)
    verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    """At least one citation's quote appears in the chunk it cites."""
    model: Mapped[str | None] = mapped_column(String(64))
    agent_run_id: Mapped[UUID | None]
    evidence_classification: Mapped[int] = mapped_column(
        SmallInteger, default=0, server_default="0"
    )
    """Highest classification among the evidence the analyst saw: viewers below it see the finding
    withheld, because a statement can carry what it read even without a valid citation."""
    support: Mapped[str] = mapped_column(
        String(16), default="unverified", server_default="unverified"
    )
    """Verification verdict (phase 15): does the cited evidence entail the statement?"""
    support_rationale: Mapped[str | None] = mapped_column(String(300))

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "job_id"],
            ["research_jobs.organization_id", "research_jobs.id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("organization_id", "id"),
        UniqueConstraint("job_id", "question_id", "ordinal"),
        CheckConstraint("evidence_classification BETWEEN 0 AND 3", name="evidence_classification"),
        CheckConstraint(f"support IN {sql_in(SUPPORT_LEVELS)}", name="support"),
        CheckConstraint(f"kind IN {sql_in(FINDING_KINDS)}", name="kind"),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="confidence"),
        Index("ix_research_findings_job", "organization_id", "job_id"),
    )


class ResearchCitation(Base, UUIDPrimaryKey, CreatedAt):
    """Evidence for a finding. Cascades from its chunk: deleting a document deletes its citations."""

    __tablename__ = "research_citations"

    organization_id: Mapped[UUID]
    finding_id: Mapped[UUID]
    chunk_id: Mapped[UUID]
    ref: Mapped[str] = mapped_column(String(8))
    quote: Mapped[str] = mapped_column(Text)
    verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["research_findings.organization_id", "research_findings.id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["organization_id", "chunk_id"],
            ["document_chunks.organization_id", "document_chunks.id"],
            ondelete="CASCADE",
        ),
        Index("ix_research_citations_finding", "organization_id", "finding_id"),
        Index("ix_research_citations_chunk", "chunk_id"),
    )


class ResearchContradiction(Base, UUIDPrimaryKey, CreatedAt):
    """Two findings from different sources that disagree, and why (never a silent choice)."""

    __tablename__ = "research_contradictions"

    organization_id: Mapped[UUID]
    job_id: Mapped[UUID]
    finding_a_id: Mapped[UUID]
    finding_b_id: Mapped[UUID]
    attribute: Mapped[str] = mapped_column(String(120))
    explanation: Mapped[str] = mapped_column(String(32))
    rationale: Mapped[str] = mapped_column(String(400))
    preferred: Mapped[str] = mapped_column(String(8), default="neither", server_default="neither")
    """``a``/``b`` only when code could verify the justification (newer date, more reliable
    source); otherwise ``neither`` and the uncertainty is presented."""
    agent_run_id: Mapped[UUID | None]

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "job_id"],
            ["research_jobs.organization_id", "research_jobs.id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["organization_id", "finding_a_id"],
            ["research_findings.organization_id", "research_findings.id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["organization_id", "finding_b_id"],
            ["research_findings.organization_id", "research_findings.id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("job_id", "finding_a_id", "finding_b_id"),
        CheckConstraint("finding_a_id <> finding_b_id", name="distinct_findings"),
        CheckConstraint(f"explanation IN {sql_in(CONTRADICTION_EXPLANATIONS)}", name="explanation"),
        CheckConstraint(f"preferred IN {sql_in(PREFERENCES)}", name="preferred"),
        Index("ix_research_contradictions_job", "organization_id", "job_id"),
    )


class ResearchReport(Base, UUIDPrimaryKey, Timestamps):
    """The composed report: canonical JSON, rendered Markdown and its quality scores."""

    __tablename__ = "research_reports"

    organization_id: Mapped[UUID]
    job_id: Mapped[UUID]
    version: Mapped[int] = mapped_column(Integer)
    content: Mapped[dict[str, Any]] = mapped_column(JSONB)
    markdown: Mapped[str] = mapped_column(Text)
    quality: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
    evidence_classification: Mapped[int] = mapped_column(
        SmallInteger, default=0, server_default="0"
    )
    """Highest classification of anything the report rests on: lower-cleared viewers cannot open
    it (a summary blends every finding, so it cannot be filtered per statement)."""

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "job_id"],
            ["research_jobs.organization_id", "research_jobs.id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("job_id", "version"),
        CheckConstraint("version >= 1", name="version_positive"),
        CheckConstraint("evidence_classification BETWEEN 0 AND 3", name="evidence_classification"),
        Index("ix_research_reports_job", "organization_id", "job_id"),
    )
