"""Dashboard overview (spec §53): one request, everything the start page shows.

Every number and list respects what the viewer may see, with the same rules as the endpoints
behind each section: restricted projects count only for their members (and owners/admins), and
each section needs its own read permission - projects ``projects:read``, jobs
``research:read``, reports ``reports:read``, sources ``sources:read``, the knowledge base
``documents:read``, monitoring ``monitors:read``, AI usage and costs ``usage:read`` (security
signals, added by the API, ``audit:read``). A section the viewer may not read is ``None``, so an
API key scoped to ``org:read`` learns no project, job or report title here either. The overview
is computed inside the organisation's row-level-security context, in one read-only snapshot.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Final
from uuid import UUID

from pydantic import BaseModel
from sqlalchemy import bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.clock import Clock
from argus.infrastructure.db import Database
from argus.modules.platform import quotas
from argus.modules.tenancy.authorization import OrgAccess
from argus.security.permissions import Permission

RECENT: Final = 8
ACTIVE_STATUSES: Final = ("queued", "running", "awaiting_approval")
_VISIBLE = text(
    "SELECT p.id FROM projects p WHERE p.organization_id = :org AND (p.visibility = 'organization'"
    " OR EXISTS (SELECT 1 FROM project_members m WHERE m.organization_id = p.organization_id"
    " AND m.project_id = p.id AND m.user_id = :user))"
)
_ALL_PROJECTS = text("SELECT id FROM projects WHERE organization_id = :org")


def _in_projects(sql: str) -> Any:
    return text(sql).bindparams(bindparam("projects", expanding=True))


_PROJECTS = _in_projects(
    "SELECT p.id, p.name, p.visibility, p.created_at,"
    " (SELECT count(*) FROM research_jobs j WHERE j.organization_id = p.organization_id"
    "  AND j.project_id = p.id) AS jobs"
    " FROM projects p WHERE p.organization_id = :org AND p.id IN :projects"
    " ORDER BY p.created_at DESC LIMIT :limit"
)
_JOB_COUNTS = _in_projects(
    "SELECT status, count(*) AS n FROM research_jobs WHERE organization_id = :org"
    " AND project_id IN :projects AND (status IN ('queued', 'running', 'awaiting_approval')"
    " OR created_at >= :since) GROUP BY status"
)
_ACTIVE_JOBS = _in_projects(
    "SELECT id, project_id, title, status, stage, progress, created_at FROM research_jobs"
    " WHERE organization_id = :org AND project_id IN :projects"
    " AND status IN ('queued', 'running', 'awaiting_approval')"
    " ORDER BY created_at DESC LIMIT :limit"
)
_REPORTS = _in_projects(
    "SELECT j.id AS job_id, j.project_id, j.title, j.finished_at FROM research_jobs j"
    " WHERE j.organization_id = :org AND j.project_id IN :projects AND j.status = 'completed'"
    " AND EXISTS (SELECT 1 FROM research_reports r WHERE r.organization_id = j.organization_id"
    " AND r.job_id = j.id) ORDER BY j.finished_at DESC NULLS LAST LIMIT :limit"
)
_SOURCES = _in_projects(
    "SELECT count(*) AS total, count(*) FILTER (WHERE status = 'blocked') AS blocked,"
    " count(*) FILTER (WHERE injection_level = 'high') AS high_risk FROM sources"
    " WHERE organization_id = :org AND project_id IN :projects"
)
_DOCUMENTS = _in_projects(
    "SELECT count(*) AS total, count(*) FILTER (WHERE status = 'ready') AS ready,"
    " count(*) FILTER (WHERE status = 'quarantined') AS quarantined,"
    " coalesce(sum(byte_size), 0) AS bytes FROM documents"
    " WHERE organization_id = :org AND project_id IN :projects"
)
_CHUNKS = _in_projects(
    "SELECT count(*) FROM document_chunks WHERE organization_id = :org AND project_id IN :projects"
)
_MONITORS = _in_projects(
    "SELECT count(*) FILTER (WHERE status = 'active') AS active, count(*) AS total FROM monitors"
    " WHERE organization_id = :org AND project_id IN :projects"
)
_CHANGES = _in_projects(
    "SELECT c.id, c.monitor_id, m.project_id, m.name AS monitor, c.summary, c.significance,"
    " c.status, c.created_at FROM monitor_changes c JOIN monitors m"
    " ON m.organization_id = c.organization_id AND m.id = c.monitor_id"
    " WHERE c.organization_id = :org AND m.project_id IN :projects"
    " ORDER BY c.created_at DESC LIMIT :limit"
)
_NEW_CHANGES = _in_projects(
    "SELECT count(*) FROM monitor_changes c JOIN monitors m"
    " ON m.organization_id = c.organization_id AND m.id = c.monitor_id"
    " WHERE c.organization_id = :org AND m.project_id IN :projects AND c.status = 'new'"
)
_UNREAD = text(
    "SELECT count(*) FROM notifications WHERE organization_id = :org AND user_id = :user"
    " AND read_at IS NULL"
)
_LLM = text(
    "SELECT coalesce(sum(cost_usd), 0) AS cost, coalesce(sum(input_tokens), 0) AS input,"
    " coalesce(sum(output_tokens), 0) AS output, count(*) AS calls,"
    " count(*) FILTER (WHERE outcome <> 'ok') AS failed FROM llm_requests"
    " WHERE organization_id = :org AND created_at >= :month"
)


class DashboardOverview(BaseModel):
    """Each section is ``None`` when the viewer lacks the permission it needs."""

    generated_at: datetime
    projects: dict[str, Any] | None
    jobs: dict[str, Any] | None
    reports: list[dict[str, Any]] | None
    sources: dict[str, int] | None
    knowledge: dict[str, int] | None
    monitoring: dict[str, Any] | None
    alerts: dict[str, int]
    ai_usage: dict[str, Any] | None


def _rows(result: Any) -> list[dict[str, Any]]:
    return [dict(row._mapping) for row in result]


class DashboardService:
    def __init__(self, database: Database, clock: Clock) -> None:
        self._db = database
        self._clock = clock

    async def overview(self, access: OrgAccess) -> DashboardOverview:
        now = self._clock.now()
        can = access.can
        async with self._db.tenant(access.scope, read_only=True, snapshot=True) as session:
            projects = await self._visible(session, access)
            params: dict[str, Any] = {
                "org": access.organization_id,
                "projects": projects or [_NO_PROJECT],
                "limit": RECENT,
                "since": now - timedelta(days=30),
                "month": quotas.month_start(now),
                "user": access.principal.user_id,
            }

            async def rows(statement: Any) -> list[dict[str, Any]]:
                return _rows(await session.execute(statement, params))

            async def one(statement: Any) -> dict[str, Any]:
                return dict((await session.execute(statement, params)).one()._mapping)

            async def count(statement: Any) -> int:
                return int((await session.execute(statement, params)).scalar_one())

            overview = DashboardOverview(
                generated_at=now,
                projects=None,
                jobs=None,
                reports=None,
                sources=None,
                knowledge=None,
                monitoring=None,
                alerts={"unread": await count(_UNREAD) if access.principal.user_id else 0},
                ai_usage=None,
            )
            if can(Permission.PROJECTS_READ):
                overview.projects = {"count": len(projects), "recent": await rows(_PROJECTS)}
            if can(Permission.RESEARCH_READ):
                by_status = {
                    row.status: row.n for row in await session.execute(_JOB_COUNTS, params)
                }
                overview.jobs = {"by_status": by_status, "active": await rows(_ACTIVE_JOBS)}
            if can(Permission.REPORTS_READ):
                overview.reports = await rows(_REPORTS)
            if can(Permission.SOURCES_READ):
                overview.sources = {k: int(v) for k, v in (await one(_SOURCES)).items()}
            if can(Permission.DOCUMENTS_READ):
                documents = await one(_DOCUMENTS)
                overview.knowledge = {
                    "documents": int(documents["total"]),
                    "ready": int(documents["ready"]),
                    "quarantined": int(documents["quarantined"]),
                    "bytes": int(documents["bytes"]),
                    "chunks": await count(_CHUNKS),
                }
            if can(Permission.MONITORS_READ):
                monitors = await one(_MONITORS)
                overview.monitoring = {
                    "active": int(monitors["active"]),
                    "total": int(monitors["total"]),
                    "new_changes": await count(_NEW_CHANGES),
                    "recent_changes": await rows(_CHANGES),
                }
            if can(Permission.USAGE_READ):
                overview.ai_usage = await self._usage(session, access, params)
            return overview

    @staticmethod
    async def _visible(session: AsyncSession, access: OrgAccess) -> list[UUID]:
        """Projects the viewer may open - the same rule as the authoriser's project check."""
        if access.is_admin:
            rows = await session.execute(_ALL_PROJECTS, {"org": access.organization_id})
        else:
            user = access.principal.user_id if access.principal.service_account_id is None else None
            rows = await session.execute(_VISIBLE, {"org": access.organization_id, "user": user})
        return list(rows.scalars())

    @staticmethod
    async def _usage(
        session: AsyncSession, access: OrgAccess, params: dict[str, Any]
    ) -> dict[str, Any]:
        llm = dict((await session.execute(_LLM, params)).one()._mapping)
        current_plan = await quotas.organization_plan(session, access.organization_id)
        budget = quotas.effective_llm_budget(access.settings.budgets.monthly_llm_usd, current_plan)
        return {
            "plan": current_plan.name,
            "cost_usd": float(llm["cost"]),
            "budget_usd": float(budget),
            "input_tokens": int(llm["input"]),
            "output_tokens": int(llm["output"]),
            "calls": int(llm["calls"]),
            "failed_calls": int(llm["failed"]),
        }


_NO_PROJECT: Final = UUID(int=0)
"""Placeholder for an empty ``IN`` list: matches no row."""
