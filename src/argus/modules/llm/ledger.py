"""Accounting and budgets for model calls.

Budgets are checked *before* a call with a pessimistic estimate (prompt tokens plus the full
``max_tokens`` at the output price) and charged *after* it with the provider's reported usage.
Three ceilings apply: the organisation's monthly budget, the research job's budget and - when
called from an agent - the agent run's (phase 14). Every attempt is recorded, failures included.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID

from sqlalchemy import select, text

from argus.core.clock import Clock
from argus.core.ids import uuid7
from argus.core.scope import Actor, TenantScope
from argus.infrastructure.db import Database
from argus.modules.llm.models import LLMRequestRecord
from argus.modules.platform import quotas
from argus.modules.tenancy.models import Organization
from argus.modules.tenancy.schemas import OrganizationSettings


@dataclass(frozen=True)
class AttemptEntry:
    task: str
    prompt_name: str
    prompt_version: int
    prompt_sha256: str
    provider: str
    model: str
    served_model: str | None
    locality: str
    classification: int
    outcome: str
    error_code: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    cost_usd: Decimal = Decimal(0)
    latency_ms: int = 0
    fallback_used: bool = False
    request_id: str | None = None


class Ledger:
    def __init__(self, database: Database, clock: Clock) -> None:
        self._db = database
        self._clock = clock

    @staticmethod
    def _scope(organization_id: UUID) -> TenantScope:
        return TenantScope(organization_id, Actor.system())

    async def organization_settings(self, organization_id: UUID) -> OrganizationSettings:
        async with self._db.tenant(self._scope(organization_id), read_only=True) as session:
            raw = (
                await session.execute(
                    select(Organization.settings).where(Organization.id == organization_id)
                )
            ).scalar_one_or_none()
        return OrganizationSettings.model_validate(raw or {})

    async def remaining(
        self, organization_id: UUID, settings: OrganizationSettings, *, job_id: UUID | None
    ) -> Decimal:
        """The smallest remaining budget that applies to a call."""
        now = self._clock.now()
        month_start = datetime(now.year, now.month, 1, tzinfo=now.tzinfo).date()
        async with self._db.tenant(self._scope(organization_id), read_only=True) as session:
            spent_month = (
                await session.execute(
                    text(
                        "SELECT coalesce(sum(cost_usd), 0) FROM llm_usage_daily "
                        "WHERE organization_id = :org AND day >= :start"
                    ),
                    {"org": organization_id, "start": month_start},
                )
            ).scalar_one()
            budget = quotas.effective_llm_budget(
                settings.budgets.monthly_llm_usd,
                await quotas.organization_plan(session, organization_id),
            )
            remaining = budget - Decimal(spent_month)
            if job_id is not None:
                row = (
                    await session.execute(
                        text("SELECT budget_usd, spent_usd FROM research_jobs WHERE id = :id"),
                        {"id": job_id},
                    )
                ).one_or_none()
                if row is not None:
                    remaining = min(remaining, Decimal(row.budget_usd) - Decimal(row.spent_usd))
        return max(remaining, Decimal(0))

    async def record(
        self,
        organization_id: UUID,
        entry: AttemptEntry,
        *,
        job_id: UUID | None,
        agent_run_id: UUID | None,
    ) -> None:
        now = self._clock.now()
        async with self._db.tenant(self._scope(organization_id)) as session:
            session.add(
                LLMRequestRecord(
                    id=uuid7(),
                    organization_id=organization_id,
                    job_id=job_id,
                    agent_run_id=agent_run_id,
                    created_at=now,
                    **entry.__dict__,
                )
            )
            await session.flush()
            if entry.input_tokens or entry.output_tokens or entry.cost_usd:
                await session.execute(
                    text(
                        "INSERT INTO llm_usage_daily (organization_id, day, provider, model, requests,"
                        " input_tokens, output_tokens, cost_usd) VALUES (:org, :day, :provider,"
                        " :model, 1, :input, :output, :cost) ON CONFLICT (organization_id, day,"
                        " provider, model) DO UPDATE SET requests = llm_usage_daily.requests + 1,"
                        " input_tokens = llm_usage_daily.input_tokens + EXCLUDED.input_tokens,"
                        " output_tokens = llm_usage_daily.output_tokens + EXCLUDED.output_tokens,"
                        " cost_usd = llm_usage_daily.cost_usd + EXCLUDED.cost_usd"
                    ),
                    {
                        "org": organization_id,
                        "day": now.date(),
                        "provider": entry.provider,
                        "model": entry.served_model or entry.model,
                        "input": entry.input_tokens
                        + entry.cache_read_tokens
                        + entry.cache_write_tokens,
                        "output": entry.output_tokens,
                        "cost": entry.cost_usd,
                    },
                )
                if job_id is not None:
                    await session.execute(
                        text(
                            "UPDATE research_jobs SET spent_usd = spent_usd + :cost,"
                            " input_tokens = input_tokens + :input,"
                            " output_tokens = output_tokens + :output WHERE id = :id"
                        ),
                        {
                            "cost": entry.cost_usd,
                            "input": entry.input_tokens,
                            "output": entry.output_tokens,
                            "id": job_id,
                        },
                    )
