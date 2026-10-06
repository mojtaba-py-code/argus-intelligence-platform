"""The research pipeline engine: ordered, checkpointed, cancellable, budget-aware stages.

* **Checkpoints** - each stage's status and (small) output is a ``research_steps`` row committed
  when the stage finishes. A worker that dies mid-job loses its lease; the next attempt resumes at
  the first unfinished stage and reads earlier outputs from the checkpoints.
* **Idempotent stages** - a stage may run twice (crash after its side effects, before its
  checkpoint), so stages upsert by natural keys (URL hash, content hash) instead of inserting.
* **Cooperative cancellation** - checked before every stage and available to long stages via
  :meth:`StageContext.check_cancelled`.
* **Approvals** - a stage raises :class:`ApprovalRequired`; the job parks in
  ``awaiting_approval`` and resumes from the same stage when a human approves.
* **Budgets** - :meth:`StageContext.charge` atomically adds cost to the job and fails the job
  when the budget is exceeded.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from decimal import Decimal
from typing import Any, Literal, Protocol
from uuid import UUID

from sqlalchemy import select, text, update

from argus.core.clock import Clock
from argus.core.errors import BudgetExceeded, PolicyViolation
from argus.core.events import Event, EventSink, NullSink
from argus.core.logging import get_logger
from argus.core.scope import Actor, ActorType, TenantScope
from argus.infrastructure.db import Database
from argus.infrastructure.observability.metrics import Metrics
from argus.infrastructure.observability.tracing import span
from argus.modules.audit.service import AuditCategory, AuditEvent, AuditOutcome, AuditService
from argus.modules.research.models import TERMINAL, ApprovalRequest, ResearchJob, ResearchStep
from argus.modules.tenancy.models import OrganizationMember

log = get_logger(__name__)
Outcome = Literal["completed", "failed", "cancelled", "awaiting_approval", "skipped"]


class ApprovalRequired(Exception):
    def __init__(self, kind: str, reason: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(reason)
        self.kind = kind
        self.reason = reason
        self.details = details or {}


class StageFailed(Exception):
    """Permanent stage failure (no retry): bad input, policy refusal, nothing to work with."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class JobCancelled(Exception):
    pass


@dataclass(frozen=True)
class JobSnapshot:
    id: UUID
    organization_id: UUID
    project_id: UUID
    objective: str
    title: str
    mode: str
    budget_usd: Decimal
    max_sources: int
    options: dict[str, Any]
    created_by_user_id: UUID | None
    created_by_api_key_id: UUID | None = None


@dataclass
class StageContext:
    job: JobSnapshot
    scope: TenantScope
    services: Any
    outputs: dict[str, dict[str, Any]]
    approvals: frozenset[str]
    _engine: ResearchPipeline
    _external_cancel: Callable[[], bool] = field(default=lambda: False)

    async def check_cancelled(self) -> None:
        if self._external_cancel() or await self._engine.cancel_requested(self.scope, self.job.id):
            raise JobCancelled

    async def charge(
        self, *, cost_usd: Decimal | float, input_tokens: int = 0, output_tokens: int = 0
    ) -> Decimal:
        """Add usage to the job; raise :class:`BudgetExceeded` once the budget is spent."""
        return await self._engine.charge(
            self.scope, self.job.id, Decimal(str(cost_usd)), input_tokens, output_tokens
        )

    async def remaining_budget(self) -> Decimal:
        return await self._engine.remaining_budget(self.scope, self.job.id)


class Stage(Protocol):
    key: str
    weight: int

    async def run(self, ctx: StageContext) -> dict[str, Any] | None: ...


def actor_for_job(job: ResearchJob | JobSnapshot) -> Actor:
    if job.created_by_user_id is not None:
        return Actor(ActorType.SYSTEM, None, job.created_by_user_id)
    return Actor.system()


class ResearchPipeline:
    def __init__(
        self,
        stages: Sequence[Stage],
        *,
        database: Database,
        audit: AuditService,
        clock: Clock,
        approval_ttl: timedelta = timedelta(days=3),
        events: EventSink | None = None,
        metrics: Metrics | None = None,
    ) -> None:
        keys = [stage.key for stage in stages]
        if len(set(keys)) != len(keys):
            msg = "stage keys must be unique"
            raise ValueError(msg)
        self.stages = list(stages)
        self._db = database
        self._audit = audit
        self._clock = clock
        self._approval_ttl = approval_ttl
        self._events: EventSink = events or NullSink()
        self._metrics = metrics

    # ---------------------------------------------------------------------- helpers
    async def cancel_requested(self, scope: TenantScope, job_id: UUID) -> bool:
        async with self._db.tenant(scope, read_only=True) as session:
            value = (
                await session.execute(
                    select(ResearchJob.cancel_requested_at).where(ResearchJob.id == job_id)
                )
            ).scalar_one_or_none()
        return value is not None

    async def charge(
        self, scope: TenantScope, job_id: UUID, cost: Decimal, input_tokens: int, output_tokens: int
    ) -> Decimal:
        async with self._db.tenant(scope) as session:
            row = (
                await session.execute(
                    text(
                        "UPDATE research_jobs SET spent_usd = spent_usd + :cost, "
                        "input_tokens = input_tokens + :tin, output_tokens = output_tokens + :tout, "
                        "updated_at = now() WHERE id = :id AND organization_id = :org "
                        "RETURNING spent_usd, budget_usd"
                    ),
                    {
                        "cost": cost,
                        "tin": input_tokens,
                        "tout": output_tokens,
                        "id": job_id,
                        "org": scope.organization_id,
                    },
                )
            ).one()
        if row.spent_usd > row.budget_usd:
            raise BudgetExceeded("The research job's cost budget has been exhausted.")
        return Decimal(row.budget_usd) - Decimal(row.spent_usd)

    async def remaining_budget(self, scope: TenantScope, job_id: UUID) -> Decimal:
        async with self._db.tenant(scope, read_only=True) as session:
            row = (
                await session.execute(
                    select(ResearchJob.budget_usd, ResearchJob.spent_usd).where(
                        ResearchJob.id == job_id
                    )
                )
            ).one()
        return Decimal(row.budget_usd) - Decimal(row.spent_usd)

    def _event(self, action: str, scope: TenantScope, job_id: UUID, **kw: Any) -> AuditEvent:
        return AuditEvent(
            action=action,
            category=AuditCategory.RESEARCH,
            actor=scope.actor,
            organization_id=scope.organization_id,
            target_type="research_job",
            target_id=str(job_id),
            **kw,
        )

    # -------------------------------------------------------------------------- run
    async def run(
        self,
        organization_id: UUID,
        job_id: UUID,
        *,
        services: Any,
        cancelled: Callable[[], bool] = lambda: False,
        final_attempt: bool = False,
    ) -> Outcome:
        provisional = TenantScope(organization_id, Actor.system())
        snapshot, approvals = await self._start(provisional, job_id)
        if snapshot is None:
            return "skipped"
        scope = TenantScope(organization_id, actor_for_job(snapshot), snapshot.project_id)
        outputs: dict[str, dict[str, Any]] = {}
        total_weight = sum(stage.weight for stage in self.stages) or 1
        done_weight = 0
        try:
            for position, stage in enumerate(self.stages):
                checkpoint = await self._checkpoint(scope, job_id, stage.key, position)
                if checkpoint is not None:
                    outputs[stage.key] = checkpoint
                    done_weight += stage.weight
                    continue
                ctx = StageContext(
                    job=snapshot,
                    scope=scope,
                    services=services,
                    outputs=outputs,
                    approvals=approvals,
                    _engine=self,
                    _external_cancel=cancelled,
                )
                await ctx.check_cancelled()
                await self._mark_step(scope, job_id, stage.key, "running")
                try:
                    with span(
                        f"research.stage {stage.key}",
                        attributes={
                            "argus.stage": stage.key,
                            "argus.job.id": job_id,
                            "argus.organization.id": organization_id,
                        },
                        expected=(ApprovalRequired, JobCancelled),
                    ):
                        output = await stage.run(ctx) or {}
                except (
                    ApprovalRequired,
                    JobCancelled,
                    StageFailed,
                    BudgetExceeded,
                    PolicyViolation,
                ):
                    await self._mark_step(scope, job_id, stage.key, "pending")
                    raise
                except Exception:
                    await self._mark_step(
                        scope, job_id, stage.key, "failed", error_code="stage_error"
                    )
                    if final_attempt:
                        await self._finish(
                            scope,
                            job_id,
                            "failed",
                            "internal_error",
                            "The research job failed after repeated errors.",
                        )
                    raise
                outputs[stage.key] = output
                done_weight += stage.weight
                await self._mark_step(
                    scope,
                    job_id,
                    stage.key,
                    "succeeded",
                    output=output,
                    progress=min(99, done_weight * 100 // total_weight),
                )
        except JobCancelled:
            await self._finish(scope, job_id, "cancelled", None, None)
            return "cancelled"
        except ApprovalRequired as required:
            await self._park_for_approval(scope, snapshot, required)
            return "awaiting_approval"
        except StageFailed as failure:
            await self._finish(scope, job_id, "failed", failure.code, failure.message)
            return "failed"
        except BudgetExceeded as exc:
            await self._finish(scope, job_id, "failed", "budget_exceeded", exc.detail)
            return "failed"
        except PolicyViolation as exc:
            await self._finish(scope, job_id, "failed", "policy_violation", exc.detail)
            return "failed"
        await self._finish(scope, job_id, "completed", None, None)
        return "completed"

    async def _start(
        self, scope: TenantScope, job_id: UUID
    ) -> tuple[JobSnapshot | None, frozenset[str]]:
        async with self._db.tenant(scope) as session:
            job = (
                await session.execute(
                    select(ResearchJob).where(ResearchJob.id == job_id).with_for_update()
                )
            ).scalar_one_or_none()
            if job is None or job.status in TERMINAL or job.status == "awaiting_approval":
                return None, frozenset()
            if job.cancel_requested_at is not None:
                job.status = "cancelled"
                job.finished_at = self._clock.now()
                return None, frozenset()
            job.status = "running"
            if job.started_at is None:
                job.started_at = self._clock.now()
            approvals = frozenset(
                (
                    await session.execute(
                        select(ApprovalRequest.kind).where(
                            ApprovalRequest.job_id == job_id, ApprovalRequest.status == "approved"
                        )
                    )
                )
                .scalars()
                .all()
            )
            snapshot = JobSnapshot(
                id=job.id,
                organization_id=job.organization_id,
                project_id=job.project_id,
                objective=job.objective,
                title=job.title,
                mode=job.mode,
                budget_usd=Decimal(job.budget_usd),
                max_sources=job.max_sources,
                options=dict(job.options or {}),
                created_by_user_id=job.created_by_user_id,
                created_by_api_key_id=job.created_by_api_key_id,
            )
            if job.stage is None:
                await self._audit.record(session, self._event("research.started", scope, job_id))
            return snapshot, approvals

    async def _checkpoint(
        self, scope: TenantScope, job_id: UUID, key: str, position: int
    ) -> dict[str, Any] | None:
        async with self._db.tenant(scope) as session:
            await session.execute(
                text(
                    "INSERT INTO research_steps (id, organization_id, job_id, key, position, status, "
                    "attempts, output, created_at, updated_at) VALUES (gen_random_uuid(), :org, :job, "
                    ":key, :pos, 'pending', 0, '{}', now(), now()) ON CONFLICT (job_id, key) DO NOTHING"
                ),
                {"org": scope.organization_id, "job": job_id, "key": key, "pos": position},
            )
            step = (
                await session.execute(
                    select(ResearchStep.status, ResearchStep.output).where(
                        ResearchStep.job_id == job_id, ResearchStep.key == key
                    )
                )
            ).one()
        return dict(step.output or {}) if step.status == "succeeded" else None

    async def _mark_step(
        self,
        scope: TenantScope,
        job_id: UUID,
        key: str,
        status: str,
        *,
        output: dict[str, Any] | None = None,
        error_code: str | None = None,
        progress: int | None = None,
    ) -> None:
        now = self._clock.now()
        values: dict[str, Any] = {"status": status, "updated_at": now}
        if status == "running":
            values.update(attempts=ResearchStep.attempts + 1, started_at=now, error_code=None)
        if status in {"succeeded", "failed"}:
            values["finished_at"] = now
        if output is not None:
            values["output"] = output
        if error_code is not None:
            values["error_code"] = error_code
        async with self._db.tenant(scope) as session:
            await session.execute(
                update(ResearchStep)
                .where(ResearchStep.job_id == job_id, ResearchStep.key == key)
                .values(**values)
            )
            job_values: dict[str, Any] = {"updated_at": now}
            if status == "running":
                job_values["stage"] = key
            if progress is not None:
                job_values["progress"] = progress
            await session.execute(
                update(ResearchJob).where(ResearchJob.id == job_id).values(**job_values)
            )

    async def _finish(
        self, scope: TenantScope, job_id: UUID, status: str, code: str | None, message: str | None
    ) -> None:
        async with self._db.tenant(scope) as session:
            job = (
                await session.execute(
                    select(ResearchJob).where(ResearchJob.id == job_id).with_for_update()
                )
            ).scalar_one()
            if job.status in TERMINAL:
                return
            job.status = status
            job.finished_at = self._clock.now()
            if self._metrics is not None and job.started_at is not None:
                self._metrics.research_duration.labels(status).observe(
                    max(0.0, (job.finished_at - job.started_at).total_seconds())
                )
            job.error_code = code
            job.error_message = message[:500] if message else None
            if status == "completed":
                job.progress = 100
            creator, project_id, title = job.created_by_user_id, job.project_id, job.title
            await self._audit.record(
                session,
                self._event(
                    f"research.{status}",
                    scope,
                    job_id,
                    outcome=AuditOutcome.SUCCESS if status == "completed" else AuditOutcome.FAILURE,
                    details={"error_code": code} if code else {},
                ),
            )
        log.info("research.finished", job_id=str(job_id), status=status, error_code=code)
        if status in {"completed", "failed"} and creator is not None:
            await self._events.emit(
                Event(
                    type="research.job.completed"
                    if status == "completed"
                    else "research.job.failed",
                    organization_id=scope.organization_id,
                    project_id=project_id,
                    title=f"Research {status}: {title}",
                    body="The report is ready."
                    if status == "completed"
                    else f"The job stopped: {message or code or 'an error occurred'}.",
                    link=f"/projects/{project_id}/research-jobs/{job_id}",
                    recipients=(creator,),
                    data={"job_id": str(job_id), "status": status, "error_code": code},
                )
            )

    async def _park_for_approval(
        self, scope: TenantScope, snapshot: JobSnapshot, required: ApprovalRequired
    ) -> None:
        async with self._db.tenant(scope) as session:
            job = (
                await session.execute(
                    select(ResearchJob).where(ResearchJob.id == snapshot.id).with_for_update()
                )
            ).scalar_one()
            pending = (
                await session.execute(
                    select(ApprovalRequest.id).where(
                        ApprovalRequest.job_id == snapshot.id,
                        ApprovalRequest.kind == required.kind,
                        ApprovalRequest.status == "pending",
                    )
                )
            ).scalar_one_or_none()
            created = pending is None
            if created:
                session.add(
                    ApprovalRequest(
                        organization_id=snapshot.organization_id,
                        project_id=snapshot.project_id,
                        job_id=snapshot.id,
                        kind=required.kind,
                        reason=required.reason[:500],
                        details=required.details,
                        expires_at=self._clock.now() + self._approval_ttl,
                    )
                )
            job.status = "awaiting_approval"
            await self._audit.record(
                session,
                self._event(
                    "research.approval_requested",
                    scope,
                    snapshot.id,
                    details={"kind": required.kind},
                ),
            )
            admins = tuple(
                (
                    await session.execute(
                        select(OrganizationMember.user_id).where(
                            OrganizationMember.organization_id == snapshot.organization_id,
                            OrganizationMember.role.in_(("owner", "admin")),
                        )
                    )
                ).scalars()
            )
        if created:
            await self._events.emit(
                Event(
                    type="approval.requested",
                    organization_id=snapshot.organization_id,
                    project_id=snapshot.project_id,
                    title=f"Approval needed ({required.kind}): {snapshot.title}",
                    body=required.reason,
                    link="/approvals",
                    recipients=admins,
                    data={"job_id": str(snapshot.id), "kind": required.kind},
                )
            )
