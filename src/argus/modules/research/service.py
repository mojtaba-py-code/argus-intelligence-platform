"""Research job use cases: create (idempotent, transactional enqueue), read, cancel, approve."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Final
from uuid import UUID

from sqlalchemy import select

from argus.core.clock import Clock
from argus.core.config import ResearchSettings
from argus.core.errors import Conflict, NotFound, PermissionDenied, RateLimited
from argus.core.pagination import Page, PageQuery, encode_cursor
from argus.core.scope import TenantScope
from argus.infrastructure.db import Database
from argus.infrastructure.idempotency import Idempotency, request_fingerprint
from argus.infrastructure.queue import JobQueue, JobSpec
from argus.modules.audit.service import AuditCategory, AuditEvent, AuditService
from argus.modules.platform import quotas
from argus.modules.research.models import TERMINAL, ApprovalRequest, ResearchJob, ResearchStep
from argus.modules.research.schemas import (
    ApprovalResponse,
    CreateResearchJobRequest,
    ResearchJobResponse,
    ResearchStepResponse,
)
from argus.modules.tenancy.authorization import OrgAccess, ProjectAccess
from argus.security.permissions import Permission
from argus.security.principals import ClientInfo, Principal
from argus.security.ratelimit import POLICIES, RateLimiter

RESEARCH_TASK = "research.run"
MODE_PERMISSIONS: Final[dict[str, tuple[Permission, ...]]] = {
    "web": (Permission.SOURCES_READ, Permission.SOURCES_MANAGE),
    "documents": (Permission.DOCUMENTS_READ,),
    "hybrid": (Permission.DOCUMENTS_READ, Permission.SOURCES_READ, Permission.SOURCES_MANAGE),
}
"""A job acts for its creator, so creating one requires what its mode will do: read the cited
origins, and (with web research) add sources to the project. Re-checked at each stage."""


def principal_key(principal: Principal) -> str:
    if principal.api_key_id is not None:
        return f"apikey:{principal.api_key_id}"
    if principal.service_account_id is not None:
        return f"sa:{principal.service_account_id}"
    return f"user:{principal.user_id}"


@dataclass(frozen=True)
class ResearchDependencies:
    database: Database
    queue: JobQueue
    audit: AuditService
    idempotency: Idempotency
    limiter: RateLimiter
    clock: Clock
    settings: ResearchSettings


@dataclass(frozen=True)
class Created:
    status: int
    body: dict[str, Any]
    job_id: UUID | None


class ResearchService:
    def __init__(self, deps: ResearchDependencies) -> None:
        self._d = deps

    def _event(
        self, action: str, scope: TenantScope, client: ClientInfo, job_id: UUID, **kw: Any
    ) -> AuditEvent:
        return AuditEvent(
            action=action,
            category=AuditCategory.RESEARCH,
            actor=scope.actor,
            organization_id=scope.organization_id,
            target_type="research_job",
            target_id=str(job_id),
            client=client,
            **kw,
        )

    async def _limit(self, policy: str, key: str) -> None:
        decision = await self._d.limiter.hit(POLICIES[policy], key)
        if not decision.allowed:
            raise RateLimited(decision.retry_after_s)

    @staticmethod
    def job_spec(job: ResearchJob, timeout_s: int) -> JobSpec:
        return JobSpec(
            task=RESEARCH_TASK,
            payload={"job_id": str(job.id), "organization_id": str(job.organization_id)},
            queue="research",
            organization_id=job.organization_id,
            max_attempts=3,
            timeout_s=timeout_s,
            dedup_key=f"research:{job.id}",
        )

    async def create(
        self,
        access: ProjectAccess,
        request: CreateResearchJobRequest,
        client: ClientInfo,
        *,
        idempotency_key: str | None,
        path: str,
    ) -> Created:
        access.require(Permission.RESEARCH_CREATE)
        missing = [p.value for p in MODE_PERMISSIONS[request.mode] if not access.can(p)]
        if missing:
            raise PermissionDenied(
                f"A {request.mode} research job needs these permissions: {', '.join(missing)}."
            )
        principal = access.org.principal
        await self._limit("research.create.org", str(access.org.organization_id))
        await self._limit("research.create.user", principal_key(principal))
        settings = self._d.settings
        budget = request.budget_usd or access.org.settings.budgets.job_default_usd
        max_sources = min(
            request.max_sources or settings.max_sources_per_job, settings.max_sources_per_job
        )
        async with self._d.database.tenant(access.scope) as session:
            if idempotency_key is not None:
                replay = await self._d.idempotency.begin(
                    session,
                    principal_key=principal_key(principal),
                    key=idempotency_key,
                    fingerprint=request_fingerprint("POST", path, request.model_dump(mode="json")),
                )
                if replay is not None:
                    return Created(replay.status, replay.body, None)
            await quotas.enforce(
                session,
                access.org.organization_id,
                "research_jobs_per_month",
                now=self._d.clock.now(),
            )
            job = ResearchJob(
                organization_id=access.org.organization_id,
                project_id=access.project_id,
                created_by_user_id=principal.user_id,
                created_by_api_key_id=principal.api_key_id,
                title=request.title
                or (request.objective[:80] + ("..." if len(request.objective) > 80 else "")),
                objective=request.objective,
                mode=request.mode,
                budget_usd=Decimal(str(budget)),
                max_sources=max_sources,
                options={},
            )
            session.add(job)
            await session.flush()
            job.queue_job_id = await self._d.queue.enqueue(
                session, self.job_spec(job, settings.job_timeout_s)
            )
            await self._d.audit.record(
                session,
                self._event(
                    "research.created",
                    access.scope,
                    client,
                    job.id,
                    details={"mode": request.mode, "budget_usd": float(budget)},
                ),
            )
            body = ResearchJobResponse.model_validate(job).model_dump(mode="json")
            if idempotency_key is not None:
                await self._d.idempotency.complete(
                    session,
                    principal_key=principal_key(principal),
                    key=idempotency_key,
                    status=202,
                    body=body,
                    resource_id=job.id,
                )
            return Created(202, body, job.id)

    async def list_jobs(
        self, access: ProjectAccess, page: PageQuery, status: str | None = None
    ) -> Page[ResearchJobResponse]:
        access.require(Permission.RESEARCH_READ)
        cursor = page.decoded()
        stmt = select(ResearchJob).where(
            ResearchJob.organization_id == access.org.organization_id,
            ResearchJob.project_id == access.project_id,
        )
        if status is not None:
            stmt = stmt.where(ResearchJob.status == status)
        if cursor is not None:
            stmt = stmt.where(
                (ResearchJob.created_at < cursor.created_at)
                | ((ResearchJob.created_at == cursor.created_at) & (ResearchJob.id < cursor.id))
            )
        stmt = stmt.order_by(ResearchJob.created_at.desc(), ResearchJob.id.desc()).limit(
            page.limit + 1
        )
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            rows = list((await session.execute(stmt)).scalars().all())
        next_cursor = None
        if len(rows) > page.limit:
            rows = rows[: page.limit]
            next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id)
        return Page[ResearchJobResponse](
            items=[ResearchJobResponse.model_validate(row) for row in rows], next_cursor=next_cursor
        )

    async def _load(
        self, session: Any, access: ProjectAccess, job_id: UUID, *, lock: bool = False
    ) -> ResearchJob:
        stmt = select(ResearchJob).where(
            ResearchJob.organization_id == access.org.organization_id,
            ResearchJob.project_id == access.project_id,
            ResearchJob.id == job_id,
        )
        if lock:
            stmt = stmt.with_for_update()
        job: ResearchJob | None = (await session.execute(stmt)).scalar_one_or_none()
        if job is None:
            raise NotFound
        return job

    async def get(self, access: ProjectAccess, job_id: UUID) -> ResearchJobResponse:
        access.require(Permission.RESEARCH_READ)
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            return ResearchJobResponse.model_validate(await self._load(session, access, job_id))

    async def steps(self, access: ProjectAccess, job_id: UUID) -> list[ResearchStepResponse]:
        access.require(Permission.RESEARCH_READ)
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            await self._load(session, access, job_id)
            rows = (
                (
                    await session.execute(
                        select(ResearchStep)
                        .where(ResearchStep.job_id == job_id)
                        .order_by(ResearchStep.position)
                    )
                )
                .scalars()
                .all()
            )
        return [ResearchStepResponse.model_validate(row) for row in rows]

    async def cancel(
        self, access: ProjectAccess, job_id: UUID, client: ClientInfo
    ) -> ResearchJobResponse:
        access.require(Permission.RESEARCH_CANCEL)
        now = self._d.clock.now()
        async with self._d.database.tenant(access.scope) as session:
            job = await self._load(session, access, job_id, lock=True)
            if job.status in TERMINAL:
                raise Conflict("The research job has already finished.")
            job.cancel_requested_at = job.cancel_requested_at or now
            immediate = job.status == "awaiting_approval"
            if job.status == "queued" and job.queue_job_id is not None:
                immediate = await self._d.queue.cancel(session, job.queue_job_id)
            if immediate:
                job.status = "cancelled"
                job.finished_at = now
                for approval in (
                    await session.execute(
                        select(ApprovalRequest).where(
                            ApprovalRequest.job_id == job_id, ApprovalRequest.status == "pending"
                        )
                    )
                ).scalars():
                    approval.status = "expired"
            await self._d.audit.record(
                session, self._event("research.cancel_requested", access.scope, client, job_id)
            )
            await session.flush()
            return ResearchJobResponse.model_validate(job)

    # ----------------------------------------------------------------------- approvals
    async def list_approvals(self, access: OrgAccess, status: str | None) -> list[ApprovalResponse]:
        access.require(Permission.APPROVALS_DECIDE)
        stmt = select(ApprovalRequest).where(
            ApprovalRequest.organization_id == access.organization_id
        )
        if status is not None:
            stmt = stmt.where(ApprovalRequest.status == status)
        stmt = stmt.order_by(ApprovalRequest.created_at.desc()).limit(200)
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            rows = (await session.execute(stmt)).scalars().all()
        return [ApprovalResponse.model_validate(row) for row in rows]

    async def decide(
        self,
        access: OrgAccess,
        approval_id: UUID,
        *,
        approve: bool,
        note: str | None,
        client: ClientInfo,
    ) -> ApprovalResponse:
        access.require(Permission.APPROVALS_DECIDE)
        now = self._d.clock.now()
        async with self._d.database.tenant(access.scope) as session:
            approval = (
                await session.execute(
                    select(ApprovalRequest)
                    .where(
                        ApprovalRequest.organization_id == access.organization_id,
                        ApprovalRequest.id == approval_id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if approval is None:
                raise NotFound
            if approval.status != "pending":
                raise Conflict("This approval request has already been decided.")
            job = (
                await session.execute(
                    select(ResearchJob).where(ResearchJob.id == approval.job_id).with_for_update()
                )
            ).scalar_one()
            if approval.expires_at <= now:
                approval.status = "expired"
                job.status, job.finished_at, job.error_code = "cancelled", now, "approval_expired"
                await session.flush()
                return ApprovalResponse.model_validate(approval)
            approval.status = "approved" if approve else "rejected"
            approval.decided_by = access.principal.user_id
            approval.decided_at = now
            approval.decision_note = note
            if approve and job.status == "awaiting_approval":
                job.status = "queued"
                job.queue_job_id = await self._d.queue.enqueue(
                    session, self.job_spec(job, self._d.settings.job_timeout_s)
                )
            elif not approve:
                job.status, job.finished_at = "cancelled", now
                job.error_code = "approval_rejected"
            await self._d.audit.record(
                session,
                AuditEvent(
                    action=f"approval.{approval.status}",
                    category=AuditCategory.AUTHORIZATION,
                    actor=access.scope.actor,
                    organization_id=access.organization_id,
                    target_type="approval_request",
                    target_id=str(approval.id),
                    client=client,
                    details={"kind": approval.kind, "job_id": str(job.id)},
                ),
            )
            await session.flush()
            return ApprovalResponse.model_validate(approval)
