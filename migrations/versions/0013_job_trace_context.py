"""Trace context on jobs: the worker continues the trace of the request that enqueued the job.

``trace_parent`` holds a W3C ``traceparent`` (55 characters) or NULL; the CHECK constraint
accepts nothing else, so the column can never become a channel for arbitrary data.

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("jobs", sa.Column("trace_parent", sa.String(length=55), nullable=True))
    op.create_check_constraint(
        op.f("ck_jobs_trace_parent"),
        "jobs",
        "trace_parent ~ '^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$'",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_jobs_trace_parent"), "jobs", type_="check")
    op.drop_column("jobs", "trace_parent")
