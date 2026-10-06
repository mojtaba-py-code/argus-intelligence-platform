"""Verification verdicts, contradictions between sources, and composed reports.

``research_findings`` gains a verification verdict (``support``) and its rationale.
``research_contradictions`` links two findings that disagree, with the explanation and the
side preferred only when code could verify the justification; it cascades from both findings.
``research_reports`` stores the canonical JSON report, its Markdown rendering, quality scores and
the highest classification it rests on. Both new tables are tenant tables (RLS, composite
same-tenant foreign keys).

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from argus.infrastructure.db import migration_support as ms

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_TABLES = ("research_contradictions", "research_reports")


def upgrade() -> None:
    op.create_table(
        "research_reports",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("content", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("markdown", sa.Text(), nullable=False),
        sa.Column(
            "quality", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False
        ),
        sa.Column("evidence_classification", sa.SmallInteger(), server_default="0", nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "evidence_classification BETWEEN 0 AND 3",
            name=op.f("ck_research_reports_evidence_classification"),
        ),
        sa.CheckConstraint("version >= 1", name=op.f("ck_research_reports_version_positive")),
        sa.ForeignKeyConstraint(
            ["organization_id", "job_id"],
            ["research_jobs.organization_id", "research_jobs.id"],
            name=op.f("fk_research_reports_organization_id_job_id_research_jobs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_research_reports")),
        sa.UniqueConstraint("job_id", "version", name=op.f("uq_research_reports_job_id_version")),
    )
    op.create_index(
        "ix_research_reports_job", "research_reports", ["organization_id", "job_id"], unique=False
    )
    op.create_table(
        "research_contradictions",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("finding_a_id", sa.Uuid(), nullable=False),
        sa.Column("finding_b_id", sa.Uuid(), nullable=False),
        sa.Column("attribute", sa.String(length=120), nullable=False),
        sa.Column("explanation", sa.String(length=32), nullable=False),
        sa.Column("rationale", sa.String(length=400), nullable=False),
        sa.Column("preferred", sa.String(length=8), server_default="neither", nullable=False),
        sa.Column("agent_run_id", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "explanation IN ('different_time_periods', 'different_scope_or_definition', "
            "'source_reliability', 'measurement_or_estimate', 'unresolved')",
            name=op.f("ck_research_contradictions_explanation"),
        ),
        sa.CheckConstraint(
            "preferred IN ('a', 'b', 'neither')", name=op.f("ck_research_contradictions_preferred")
        ),
        sa.CheckConstraint(
            "finding_a_id <> finding_b_id",
            name=op.f("ck_research_contradictions_distinct_findings"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "finding_a_id"],
            ["research_findings.organization_id", "research_findings.id"],
            name=op.f("fk_research_contradictions_organization_id_finding_a_id_research_findings"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "finding_b_id"],
            ["research_findings.organization_id", "research_findings.id"],
            name=op.f("fk_research_contradictions_organization_id_finding_b_id_research_findings"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "job_id"],
            ["research_jobs.organization_id", "research_jobs.id"],
            name=op.f("fk_research_contradictions_organization_id_job_id_research_jobs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_research_contradictions")),
        sa.UniqueConstraint(
            "job_id",
            "finding_a_id",
            "finding_b_id",
            name=op.f("uq_research_contradictions_job_id_finding_a_id_finding_b_id"),
        ),
    )
    op.create_index(
        "ix_research_contradictions_job",
        "research_contradictions",
        ["organization_id", "job_id"],
        unique=False,
    )
    op.add_column(
        "research_findings",
        sa.Column("support", sa.String(length=16), server_default="unverified", nullable=False),
    )
    op.add_column(
        "research_findings", sa.Column("support_rationale", sa.String(length=300), nullable=True)
    )
    # Autogenerate does not detect CHECK constraints on existing tables.
    op.create_check_constraint(
        op.f("ck_research_findings_support"),
        "research_findings",
        "support IN ('unverified', 'supported', 'partial', 'unsupported', 'contradicted')",
    )
    for table in _TENANT_TABLES:
        op.execute(ms.grant_dml(table))
        for statement in ms.tenant_rls(table):
            op.execute(statement)


def downgrade() -> None:
    op.drop_constraint(op.f("ck_research_findings_support"), "research_findings", type_="check")
    op.drop_column("research_findings", "support_rationale")
    op.drop_column("research_findings", "support")
    op.drop_index("ix_research_contradictions_job", table_name="research_contradictions")
    op.drop_table("research_contradictions")
    op.drop_index("ix_research_reports_job", table_name="research_reports")
    op.drop_table("research_reports")
