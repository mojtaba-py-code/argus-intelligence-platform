"""Plan quotas: enforced in the same transaction as the change they limit, and reported.

Usage is computed from the tables themselves (no separate counters that can drift), and every
check takes a transaction-scoped advisory lock per organisation and metric: two concurrent
requests can never both see "one left" and both succeed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Final
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import TextClause

from argus.core.errors import QuotaExceeded
from argus.modules.platform.plans import METRICS, Metric, Plan, plan
from argus.modules.tenancy.models import Organization

plan_for = plan
"""The plan object for a stored plan name (re-exported for the modules that enforce quotas)."""

_USAGE: Final[dict[Metric, TextClause]] = {
    "members": text(
        "SELECT (SELECT count(*) FROM organization_members WHERE organization_id = :org)"
        " + (SELECT count(*) FROM invitations WHERE organization_id = :org"
        " AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > :now)"
    ),
    "projects": text("SELECT count(*) FROM projects WHERE organization_id = :org"),
    "monitors": text("SELECT count(*) FROM monitors WHERE organization_id = :org"),
    "api_keys": text(
        "SELECT count(*) FROM api_keys WHERE organization_id = :org AND revoked_at IS NULL"
        " AND (expires_at IS NULL OR expires_at > :now)"
    ),
    "research_jobs_per_month": text(
        "SELECT count(*) FROM research_jobs WHERE organization_id = :org AND created_at >= :month"
    ),
    "storage_bytes": text(
        "SELECT coalesce(sum(byte_size), 0) FROM documents WHERE organization_id = :org"
    ),
}
_LLM_SPEND = text(
    "SELECT coalesce(sum(cost_usd), 0) FROM llm_usage_daily"
    " WHERE organization_id = :org AND day >= :month"
)
_LABELS: Final[dict[Metric, str]] = {
    "members": "members and open invitations",
    "projects": "projects",
    "monitors": "monitors",
    "api_keys": "active API keys",
    "research_jobs_per_month": "research jobs per month",
    "storage_bytes": "of document storage",
}


def month_start(now: datetime) -> datetime:
    current = now.astimezone(UTC)
    return datetime(current.year, current.month, 1, tzinfo=UTC)


def _amount(metric: Metric, value: int) -> str:
    if metric == "storage_bytes":
        return f"{value / 1024**3:.1f} GiB"
    return f"{value:,}"


async def organization_plan(session: AsyncSession, organization_id: UUID) -> Plan:
    name = (
        await session.execute(select(Organization.plan).where(Organization.id == organization_id))
    ).scalar_one_or_none()
    return plan(name or "free")


async def usage(
    session: AsyncSession, organization_id: UUID, metric: Metric, *, now: datetime
) -> int:
    value = (
        await session.execute(
            _USAGE[metric], {"org": organization_id, "now": now, "month": month_start(now)}
        )
    ).scalar_one()
    return int(value)


async def enforce(
    session: AsyncSession,
    organization_id: UUID,
    metric: Metric,
    *,
    now: datetime,
    adding: int = 1,
) -> None:
    """Raise :class:`QuotaExceeded` when ``adding`` more would exceed the plan. Call it inside
    the transaction that makes the change, before the change."""
    current_plan = await organization_plan(session, organization_id)
    limit = current_plan.limit(metric)
    if limit is None:
        return
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"argus:quota:{organization_id}:{metric}"},
    )
    used = await usage(session, organization_id, metric, now=now)
    if used + adding > limit:
        raise QuotaExceeded(
            f"The {current_plan.name} plan allows {_amount(metric, limit)} {_LABELS[metric]};"
            f" this organisation uses {_amount(metric, used)}. Remove something or upgrade."
        )


def effective_llm_budget(organization_budget: float, current_plan: Plan) -> Decimal:
    """The organisation's own monthly model budget, capped by its plan."""
    budget = Decimal(str(organization_budget))
    if current_plan.monthly_llm_usd is None:
        return budget
    return min(budget, Decimal(str(current_plan.monthly_llm_usd)))


async def report(
    session: AsyncSession, organization_id: UUID, *, now: datetime, organization_budget: float
) -> dict[str, object]:
    current_plan = await organization_plan(session, organization_id)
    metrics = {
        metric: {
            "used": await usage(session, organization_id, metric, now=now),
            "limit": current_plan.limit(metric),
        }
        for metric in METRICS
    }
    spent = (
        await session.execute(
            _LLM_SPEND, {"org": organization_id, "month": month_start(now).date()}
        )
    ).scalar_one()
    return {
        "plan": current_plan.name,
        "period_start": month_start(now),
        "metrics": metrics,
        "llm": {
            "spent_usd": float(spent),
            "budget_usd": float(effective_llm_budget(organization_budget, current_plan)),
            "plan_ceiling_usd": current_plan.monthly_llm_usd,
        },
    }
