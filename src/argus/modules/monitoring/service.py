"""Monitors: watch pages (or search results) on a schedule and alert on meaningful change.

A run, for each target: collect the page through ``SourceService.collect`` (SSRF guard, robots,
politeness, domain policies, injection assessment - exactly as research does), compare the new
snapshot with the one the monitor last saw, score the noise-filtered difference in code, let the
monitoring agent judge the strongest changes, and alert only when the result clears the monitor's
threshold. A monitor acts for its creator and is re-authorised on every run: a creator who lost
access pauses the monitor and the organisation's administrators are told.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final
from uuid import UUID

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.classification import Classification
from argus.core.clock import Clock
from argus.core.config import MonitoringSettings
from argus.core.errors import Conflict, NotFound, PermissionDenied, RateLimited, ValidationFailed
from argus.core.events import Event, EventSink
from argus.core.ids import uuid7
from argus.core.logging import get_logger
from argus.core.pagination import Page, PageQuery, encode_cursor
from argus.core.scope import Actor, TenantScope
from argus.infrastructure.db import Database
from argus.infrastructure.queue import JobQueue, JobSpec
from argus.modules.agents.runtime import AgentContext, AgentRuntime
from argus.modules.audit.service import AuditCategory, AuditEvent, AuditService
from argus.modules.monitoring.assess import (
    MONITOR_ASSESSOR,
    ChangeAssessment,
    change_block,
    combined,
    safe_summary,
)
from argus.modules.monitoring.diff import diff, significance
from argus.modules.monitoring.models import Monitor, MonitorChange, MonitorTarget
from argus.modules.monitoring.schemas import (
    CreateMonitorRequest,
    MonitorChangeResponse,
    MonitorResponse,
    MonitorTargetResponse,
    UpdateMonitorRequest,
)
from argus.modules.platform import quotas
from argus.modules.research.reporting import prose
from argus.modules.sources.models import SourceSnapshot
from argus.modules.sources.search import SearchProvider
from argus.modules.sources.service import SourceService
from argus.modules.tenancy import creators
from argus.modules.tenancy.authorization import Authorizer, ProjectAccess
from argus.modules.tenancy.models import OrganizationMember
from argus.security.permissions import Permission
from argus.security.principals import ClientInfo
from argus.security.ratelimit import POLICIES, RateLimiter
from argus.security.ssrf import EgressBlocked, parse_url
from argus.security.text import clean_line

log = get_logger(__name__)
RUN_TASK: Final = "monitoring.run"
REQUIRED: Final = (Permission.MONITORS_MANAGE, Permission.SOURCES_MANAGE, Permission.SOURCES_READ)
"""A monitor adds pages to the project's sources, so it needs what adding them needs."""


@dataclass(frozen=True)
class MonitorDependencies:
    database: Database
    queue: JobQueue
    sources: SourceService
    search: SearchProvider
    agents: AgentRuntime
    authorizer: Authorizer
    events: EventSink
    audit: AuditService
    limiter: RateLimiter
    clock: Clock
    settings: MonitoringSettings
    allowed_ports: tuple[int, ...]


class MonitorService:
    def __init__(self, deps: MonitorDependencies) -> None:
        self._d = deps

    # ------------------------------------------------------------------------- helpers
    def _audit(
        self,
        action: str,
        access: ProjectAccess,
        client: ClientInfo,
        monitor_id: UUID,
        **details: Any,
    ) -> AuditEvent:
        return AuditEvent(
            action=action,
            category=AuditCategory.CONFIGURATION,
            actor=access.scope.actor,
            organization_id=access.org.organization_id,
            target_type="monitor",
            target_id=str(monitor_id),
            client=client,
            details=details,
        )

    @staticmethod
    def _require(access: ProjectAccess) -> None:
        missing = [p.value for p in REQUIRED if not access.can(p)]
        if missing:
            raise PermissionDenied(f"Monitors need these permissions: {', '.join(missing)}.")

    def _urls(self, raw: list[str]) -> list[str]:
        urls: list[str] = []
        for value in raw:
            try:
                urls.append(str(parse_url(value, allowed_ports=self._d.allowed_ports)))
            except EgressBlocked as exc:
                raise ValidationFailed(
                    f"This address cannot be monitored ({exc.reason})."
                ) from None
        unique = list(dict.fromkeys(urls))
        if len(unique) > self._d.settings.max_targets:
            raise ValidationFailed(
                f"A monitor watches at most {self._d.settings.max_targets} pages."
            )
        return unique

    async def _load(
        self, session: AsyncSession, access: ProjectAccess, monitor_id: UUID
    ) -> Monitor:
        monitor = (
            await session.execute(
                select(Monitor).where(
                    Monitor.organization_id == access.org.organization_id,
                    Monitor.project_id == access.project_id,
                    Monitor.id == monitor_id,
                )
            )
        ).scalar_one_or_none()
        if monitor is None:
            raise NotFound
        return monitor

    @staticmethod
    async def _targets(session: AsyncSession, monitor: Monitor) -> list[MonitorTarget]:
        return list(
            (
                await session.execute(
                    select(MonitorTarget)
                    .where(
                        MonitorTarget.organization_id == monitor.organization_id,
                        MonitorTarget.monitor_id == monitor.id,
                    )
                    .order_by(MonitorTarget.created_at, MonitorTarget.id)
                )
            )
            .scalars()
            .all()
        )

    @staticmethod
    def _response(monitor: Monitor, targets: list[MonitorTarget]) -> MonitorResponse:
        return MonitorResponse.model_validate(monitor).model_copy(
            update={"targets": [MonitorTargetResponse.model_validate(t) for t in targets]}
        )

    # ----------------------------------------------------------------------- API: CRUD
    async def create(
        self, access: ProjectAccess, request: CreateMonitorRequest, client: ClientInfo
    ) -> MonitorResponse:
        self._require(access)
        urls = self._urls(request.urls)
        queries = list(dict.fromkeys(q for q in (clean_line(x, 200) for x in request.queries) if q))
        if len(queries) > self._d.settings.max_queries:
            raise ValidationFailed(
                f"A monitor runs at most {self._d.settings.max_queries} queries."
            )
        principal = access.org.principal
        monitor_id = uuid7()
        async with self._d.database.tenant(access.scope) as session:
            count = (
                await session.execute(
                    select(func.count())
                    .select_from(Monitor)
                    .where(Monitor.organization_id == access.org.organization_id)
                )
            ).scalar_one()
            if count >= self._d.settings.max_monitors_per_org:
                raise Conflict("This organisation has reached its monitor limit.")
            await quotas.enforce(
                session, access.org.organization_id, "monitors", now=self._d.clock.now()
            )
            monitor = Monitor(
                id=monitor_id,
                organization_id=access.org.organization_id,
                project_id=access.project_id,
                name=request.name,
                kind=request.kind,
                queries=queries,
                topics=list(dict.fromkeys(request.topics)),
                interval_minutes=request.interval_minutes,
                significance_threshold=request.significance_threshold,
                notify_email=request.notify_email,
                status="active",
                next_run_at=self._d.clock.now(),  # the first run records the baseline
                created_by_user_id=principal.user_id,
                created_by_api_key_id=principal.api_key_id,
            )
            session.add(monitor)
            targets = [
                MonitorTarget(
                    organization_id=access.org.organization_id, monitor_id=monitor_id, url=url
                )
                for url in urls
            ]
            session.add_all(targets)
            await session.flush()
            await self._d.audit.record(
                session,
                self._audit(
                    "monitor.created",
                    access,
                    client,
                    monitor_id,
                    kind=request.kind,
                    targets=len(urls),
                    queries=len(queries),
                ),
            )
            return self._response(monitor, targets)

    async def list_monitors(self, access: ProjectAccess, page: PageQuery) -> Page[MonitorResponse]:
        access.require(Permission.MONITORS_READ)
        cursor = page.decoded()
        stmt = select(Monitor).where(
            Monitor.organization_id == access.org.organization_id,
            Monitor.project_id == access.project_id,
        )
        if cursor is not None:
            stmt = stmt.where(
                (Monitor.created_at < cursor.created_at)
                | ((Monitor.created_at == cursor.created_at) & (Monitor.id < cursor.id))
            )
        stmt = stmt.order_by(Monitor.created_at.desc(), Monitor.id.desc()).limit(page.limit + 1)
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            rows = list((await session.execute(stmt)).scalars().all())
        next_cursor = None
        if len(rows) > page.limit:
            rows = rows[: page.limit]
            next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id)
        return Page[MonitorResponse](
            items=[MonitorResponse.model_validate(row) for row in rows], next_cursor=next_cursor
        )

    async def get(self, access: ProjectAccess, monitor_id: UUID) -> MonitorResponse:
        access.require(Permission.MONITORS_READ)
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            monitor = await self._load(session, access, monitor_id)
            return self._response(monitor, await self._targets(session, monitor))

    async def update(
        self,
        access: ProjectAccess,
        monitor_id: UUID,
        request: UpdateMonitorRequest,
        client: ClientInfo,
    ) -> MonitorResponse:
        self._require(access)
        changes = request.model_dump(exclude_none=True)
        async with self._d.database.tenant(access.scope) as session:
            monitor = await self._load(session, access, monitor_id)
            for field, value in changes.items():
                setattr(monitor, field, list(dict.fromkeys(value)) if field == "topics" else value)
            if changes.get("status") == "active":
                monitor.next_run_at = self._d.clock.now()
                monitor.last_error_code = None
            await session.flush()
            await self._d.audit.record(
                session,
                self._audit("monitor.updated", access, client, monitor_id, fields=sorted(changes)),
            )
            return self._response(monitor, await self._targets(session, monitor))

    async def delete(self, access: ProjectAccess, monitor_id: UUID, client: ClientInfo) -> None:
        self._require(access)
        async with self._d.database.tenant(access.scope) as session:
            monitor = await self._load(session, access, monitor_id)
            await session.delete(monitor)  # targets and changes cascade
            await self._d.audit.record(
                session, self._audit("monitor.deleted", access, client, monitor_id)
            )

    async def run_now(self, access: ProjectAccess, monitor_id: UUID, client: ClientInfo) -> None:
        self._require(access)
        principal = access.org.principal
        key = str(principal.api_key_id or principal.user_id or principal.service_account_id)
        decision = await self._d.limiter.hit(POLICIES["monitors.run.user"], key)
        if not decision.allowed:
            raise RateLimited(decision.retry_after_s)
        async with self._d.database.tenant(access.scope) as session:
            monitor = await self._load(session, access, monitor_id)
            if monitor.status != "active":
                raise Conflict("Resume the monitor before running it.")
            await self._d.queue.enqueue(session, self._job(monitor.organization_id, monitor.id))
            await self._d.audit.record(
                session, self._audit("monitor.run_requested", access, client, monitor_id)
            )

    def _job(self, organization_id: UUID, monitor_id: UUID) -> JobSpec:
        return JobSpec(
            task=RUN_TASK,
            payload={"organization_id": str(organization_id), "monitor_id": str(monitor_id)},
            queue="monitoring",
            organization_id=organization_id,
            max_attempts=2,
            timeout_s=900,
            dedup_key=f"monitor:{monitor_id}",
        )

    # ------------------------------------------------------------------- API: changes
    async def changes(
        self,
        access: ProjectAccess,
        monitor_id: UUID,
        page: PageQuery,
        *,
        status: str | None = None,
    ) -> Page[MonitorChangeResponse]:
        access.require(Permission.MONITORS_READ)
        cursor = page.decoded()
        stmt = (
            select(MonitorChange, MonitorTarget.url)
            .join(MonitorTarget, MonitorTarget.id == MonitorChange.target_id)
            .where(
                MonitorChange.organization_id == access.org.organization_id,
                MonitorChange.monitor_id == monitor_id,
            )
        )
        if status is not None:
            stmt = stmt.where(MonitorChange.status == status)
        if cursor is not None:
            stmt = stmt.where(
                (MonitorChange.created_at < cursor.created_at)
                | ((MonitorChange.created_at == cursor.created_at) & (MonitorChange.id < cursor.id))
            )
        stmt = stmt.order_by(MonitorChange.created_at.desc(), MonitorChange.id.desc()).limit(
            page.limit + 1
        )
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            await self._load(session, access, monitor_id)
            rows = list((await session.execute(stmt)).all())
        next_cursor = None
        if len(rows) > page.limit:
            rows = rows[: page.limit]
            next_cursor = encode_cursor(rows[-1][0].created_at, rows[-1][0].id)
        return Page[MonitorChangeResponse](
            items=[self._change(change, url) for change, url in rows], next_cursor=next_cursor
        )

    @staticmethod
    def _change(change: MonitorChange, url: str) -> MonitorChangeResponse:
        return MonitorChangeResponse.model_validate(
            {
                **{c.name: getattr(change, c.name) for c in MonitorChange.__table__.columns},
                "url": url,
            }
        )

    async def decide_change(
        self,
        access: ProjectAccess,
        monitor_id: UUID,
        change_id: UUID,
        status: str,
        client: ClientInfo,
    ) -> MonitorChangeResponse:
        access.require(Permission.MONITORS_MANAGE)
        async with self._d.database.tenant(access.scope) as session:
            await self._load(session, access, monitor_id)
            row = (
                await session.execute(
                    select(MonitorChange, MonitorTarget.url)
                    .join(MonitorTarget, MonitorTarget.id == MonitorChange.target_id)
                    .where(
                        MonitorChange.organization_id == access.org.organization_id,
                        MonitorChange.monitor_id == monitor_id,
                        MonitorChange.id == change_id,
                    )
                )
            ).one_or_none()
            if row is None:
                raise NotFound
            change, url = row
            change.status = status
            await session.flush()
            await self._d.audit.record(
                session,
                self._audit(
                    "monitor.change_" + status, access, client, monitor_id, change_id=str(change_id)
                ),
            )
            return self._change(change, url)

    # ------------------------------------------------------------------------ scheduling
    async def dispatch_due(self) -> int:
        """Claim due monitors in every organisation (a narrow SECURITY DEFINER function that
        returns identifiers only) and queue one run for each."""
        async with self._d.database.session() as session:
            rows = (
                await session.execute(
                    text("SELECT organization_id, monitor_id FROM argus_claim_due_monitors(:n)"),
                    {"n": self._d.settings.dispatch_batch},
                )
            ).all()
            for row in rows:
                await self._d.queue.enqueue(session, self._job(row.organization_id, row.monitor_id))
        return len(rows)

    # -------------------------------------------------------------------------- one run
    async def execute(self, organization_id: UUID, monitor_id: UUID) -> dict[str, Any]:
        system = TenantScope(organization_id, Actor.system())
        async with self._d.database.tenant(system, read_only=True) as session:
            monitor = (
                await session.execute(
                    select(Monitor).where(
                        Monitor.organization_id == organization_id, Monitor.id == monitor_id
                    )
                )
            ).scalar_one_or_none()
        if monitor is None or monitor.status != "active":
            return {"skipped": "missing or paused"}
        try:
            access = await creators.creator_access(
                self._d.database,
                self._d.authorizer,
                system,
                monitor.project_id,
                user_id=monitor.created_by_user_id,
                api_key_id=monitor.created_by_api_key_id,
                now=self._d.clock.now(),
            )
            self._require(access)
        except (creators.CreatorRevoked, PermissionDenied):
            await self._pause(monitor, "access_revoked")
            return {"paused": "access_revoked"}
        scope = access.scope
        if monitor.kind == "search":
            await self._discover(scope, monitor)
        policies = await self._d.sources.domain_policies(scope)
        async with self._d.database.tenant(scope, read_only=True) as session:
            targets = await self._targets(session, monitor)
        found: list[tuple[MonitorChange, Any, str]] = []
        for target in targets:
            change = await self._check(scope, monitor, target, policies)
            if change is not None:
                found.append(change)
        alerts = await self._assess_and_alert(monitor, access, found)
        async with self._d.database.tenant(scope) as session:
            await session.execute(
                update(Monitor)
                .where(Monitor.organization_id == organization_id, Monitor.id == monitor_id)
                .values(last_run_at=self._d.clock.now(), last_error_code=None)
            )
        return {"targets": len(targets), "changes": len(found), "alerts": alerts}

    async def _discover(self, scope: TenantScope, monitor: Monitor) -> None:
        urls: list[str] = []
        for query in monitor.queries:
            try:
                results = await self._d.search.search(
                    query, limit=self._d.settings.results_per_query
                )
            except Exception as exc:  # noqa: BLE001 - a provider outage skips discovery only
                log.warning("monitoring.search_failed", error=type(exc).__name__)
                continue
            for result in results:
                try:
                    urls.append(str(parse_url(result.url, allowed_ports=self._d.allowed_ports)))
                except EgressBlocked:
                    continue
        urls = list(dict.fromkeys(urls))[: self._d.settings.max_targets]
        async with self._d.database.tenant(scope) as session:
            known = {t.url for t in await self._targets(session, monitor)}
            session.add_all(
                MonitorTarget(
                    organization_id=monitor.organization_id,
                    monitor_id=monitor.id,
                    url=url,
                    discovered=True,
                )
                for url in urls
                if url not in known
            )
            await session.flush()
            # Keep the newest discoveries within the cap; people's chosen URLs are never dropped.
            discovered = [t for t in await self._targets(session, monitor) if t.discovered]
            excess = len(discovered) - self._d.settings.max_targets
            if excess > 0:
                await session.execute(
                    delete(MonitorTarget).where(
                        MonitorTarget.id.in_([t.id for t in discovered[:excess]])
                    )
                )

    async def _check(
        self, scope: TenantScope, monitor: Monitor, target: MonitorTarget, policies: Any
    ) -> tuple[MonitorChange, Any, str] | None:
        try:
            outcome = await self._d.sources.collect(
                scope, target.url, discovered_via="monitor", policies=policies
            )
        except EgressBlocked as exc:
            await self._mark(scope, target, "blocked", exc.reason[:48])
            return None
        if outcome.status != "fetched" or outcome.snapshot_id is None:
            await self._mark(scope, target, outcome.status, outcome.error_code)
            return None
        previous = target.last_snapshot_id
        async with self._d.database.tenant(scope) as session:
            await session.execute(
                update(MonitorTarget)
                .where(MonitorTarget.id == target.id)
                .values(
                    source_id=outcome.source_id,
                    last_snapshot_id=outcome.snapshot_id,
                    last_checked_at=self._d.clock.now(),
                    last_status="fetched",
                    last_error_code=None,
                )
            )
            if previous is None or previous == outcome.snapshot_id:
                return None  # first look (baseline) or unchanged
            texts = dict(
                (
                    await session.execute(
                        select(SourceSnapshot.id, SourceSnapshot.text).where(
                            SourceSnapshot.organization_id == monitor.organization_id,
                            SourceSnapshot.id.in_([previous, outcome.snapshot_id]),
                        )
                    )
                ).all()
            )
            change = diff(texts.get(previous, ""), texts.get(outcome.snapshot_id, ""))
            if change.empty:
                return None  # only noise changed (dates, counters, tokens)
            score, topics = significance(change, monitor.topics)
            record = MonitorChange(
                id=uuid7(),
                organization_id=monitor.organization_id,
                monitor_id=monitor.id,
                target_id=target.id,
                previous_snapshot_id=previous,
                snapshot_id=outcome.snapshot_id,
                topics=topics,
                significance=score,
                summary=safe_summary(None, change),
                # Shown through the API: sanitised and defanged like any report text.
                diff={
                    side: [prose(line, 300) for line in lines]
                    for side, lines in change.excerpt().items()
                },
            )
            session.add(record)
        return record, change, target.url

    async def _mark(
        self, scope: TenantScope, target: MonitorTarget, status: str, error: str | None
    ) -> None:
        async with self._d.database.tenant(scope) as session:
            await session.execute(
                update(MonitorTarget)
                .where(MonitorTarget.id == target.id)
                .values(
                    last_checked_at=self._d.clock.now(),
                    last_status=status[:16],
                    last_error_code=(error or None) and error[:48],
                )
            )

    async def _assess_and_alert(
        self,
        monitor: Monitor,
        access: ProjectAccess,
        found: list[tuple[MonitorChange, Any, str]],
    ) -> int:
        settings = self._d.settings
        ranked = sorted(found, key=lambda item: -item[0].significance)
        assessed = 0
        alerts = 0
        recipients = await self._recipients(monitor)
        for record, change, url in ranked:
            assessment: ChangeAssessment | None = None
            run_id = None
            if (
                record.significance >= settings.assessment_floor
                and assessed < settings.max_assessed_changes
            ):
                assessed += 1
                outcome = await self._d.agents.run(
                    MONITOR_ASSESSOR,
                    variables={"monitor": monitor.name, "topics": list(monitor.topics)},
                    evidence=[change_block(url, change)],
                    tools={},
                    context=AgentContext(organization_id=monitor.organization_id),
                    classification=Classification.PUBLIC,
                )
                run_id = outcome.run_id
                if isinstance(outcome.output, ChangeAssessment):
                    assessment = outcome.output
            final = combined(record.significance, assessment)
            topics = list(
                dict.fromkeys([*record.topics, *(assessment.topics if assessment else [])])
            )
            summary = safe_summary(assessment, change)
            alert = (
                record.significance >= settings.assessment_floor
                and final >= monitor.significance_threshold
            )
            async with self._d.database.tenant(access.scope) as session:
                await session.execute(
                    update(MonitorChange)
                    .where(MonitorChange.id == record.id)
                    .values(
                        significance=final,
                        topics=topics,
                        summary=summary,
                        alerted=alert,
                        agent_run_id=run_id,
                    )
                )
            if alert and recipients:
                alerts += 1
                await self._d.events.emit(
                    Event(
                        type="monitor.change.detected",
                        organization_id=monitor.organization_id,
                        project_id=monitor.project_id,
                        title=f"{monitor.name}: change detected",
                        body=(
                            f"{summary}\n\nPage: {parse_url(url).host}\nTopics: "
                            f"{', '.join(topics) or '-'}\nSignificance: {final:.2f}"
                        ),
                        link=f"/projects/{monitor.project_id}/monitors/{monitor.id}/changes/{record.id}",
                        recipients=recipients,
                        email=monitor.notify_email,
                        data={"monitor_id": str(monitor.id), "change_id": str(record.id)},
                    )
                )
        return alerts

    async def _recipients(self, monitor: Monitor) -> tuple[UUID, ...]:
        """The person behind the monitor; for service-account monitors, the administrators."""
        if monitor.created_by_user_id is not None:
            return (monitor.created_by_user_id,)
        scope = TenantScope(monitor.organization_id, Actor.system())
        async with self._d.database.tenant(scope, read_only=True) as session:
            return tuple(
                (
                    await session.execute(
                        select(OrganizationMember.user_id).where(
                            OrganizationMember.organization_id == monitor.organization_id,
                            OrganizationMember.role.in_(("owner", "admin")),
                        )
                    )
                ).scalars()
            )

    async def _pause(self, monitor: Monitor, code: str) -> None:
        scope = TenantScope(monitor.organization_id, Actor.system())
        async with self._d.database.tenant(scope) as session:
            await session.execute(
                update(Monitor)
                .where(Monitor.organization_id == monitor.organization_id, Monitor.id == monitor.id)
                .values(status="paused", last_error_code=code, last_run_at=self._d.clock.now())
            )
            admins = tuple(
                (
                    await session.execute(
                        select(OrganizationMember.user_id).where(
                            OrganizationMember.organization_id == monitor.organization_id,
                            OrganizationMember.role.in_(("owner", "admin")),
                        )
                    )
                ).scalars()
            )
        await self._d.events.emit(
            Event(
                type="monitor.paused",
                organization_id=monitor.organization_id,
                project_id=monitor.project_id,
                title=f"{monitor.name}: monitor paused",
                body="The monitor was paused because the person or key that created it no longer "
                "has the access it needs. Review it and resume it under an account that does.",
                link=f"/projects/{monitor.project_id}/monitors/{monitor.id}",
                recipients=admins,
                data={"monitor_id": str(monitor.id), "reason": code},
            )
        )
