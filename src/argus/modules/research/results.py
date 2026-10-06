"""Reading a job's results: the plan, verified findings with citations, and the agent trail.

A job is run with its *creator's* rights; its results are read with the *viewer's*. Three rules
keep a viewer from seeing more than they could find themselves:

* Findings and the agent trail require read access to every origin the job's mode used
  (``documents:read`` and/or ``sources:read``), on top of ``research:read``.
* A finding whose analyst read evidence above the viewer's classification ceiling is **withheld**:
  the statement and citations are removed and only the fact that it exists remains. A model's
  sentence can carry what it read whether or not it cited it, so per-citation filtering alone is
  not enough.
* A citation is shown only when its chunk is within the viewer's ceiling; the rest are counted.
  Agent runs that saw evidence above the ceiling are shown without tool arguments and results.

``verified`` is recomputed at read time from the citations that still exist: deleting a document
deletes its citations (``ON DELETE CASCADE``), so a finding that rested on it stops being
presented as verified.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Final, Literal
from uuid import UUID

from sqlalchemy import func, select

from argus.core.config import ReportSettings
from argus.core.errors import NotFound, PermissionDenied, RateLimited
from argus.infrastructure.db import Database
from argus.modules.agents.models import AgentRun, ToolCallRecord
from argus.modules.audit.service import AuditCategory, AuditEvent, AuditService
from argus.modules.documents.models import Document
from argus.modules.knowledge.models import DocumentChunk
from argus.modules.research.exports import render_csv, render_json, render_markdown, render_pdf
from argus.modules.research.models import (
    ResearchCitation,
    ResearchContradiction,
    ResearchFinding,
    ResearchJob,
    ResearchPlan,
    ResearchReport,
)
from argus.modules.research.report_model import ReportDocument
from argus.modules.research.schemas import (
    AgentRunView,
    CitationView,
    ContradictionsResponse,
    ContradictionView,
    FindingsResponse,
    FindingView,
    ResearchPlanResponse,
    ToolCallView,
)
from argus.modules.sources.models import Source
from argus.modules.tenancy.authorization import ProjectAccess
from argus.security.permissions import Permission
from argus.security.principals import ClientInfo
from argus.security.ratelimit import POLICIES, RateLimiter

ExportFormat = Literal["markdown", "json", "csv", "pdf"]

MODE_READ: Final[dict[str, tuple[Permission, ...]]] = {
    "web": (Permission.SOURCES_READ,),
    "documents": (Permission.DOCUMENTS_READ,),
    "hybrid": (Permission.DOCUMENTS_READ, Permission.SOURCES_READ),
}
_ORIGIN_PERMISSION: Final = {
    "document": Permission.DOCUMENTS_READ,
    "web": Permission.SOURCES_READ,
}


@dataclass(frozen=True)
class Export:
    content: bytes
    media_type: str
    filename: str


_MEDIA: Final[dict[str, tuple[str, str]]] = {
    "markdown": ("text/markdown; charset=utf-8", "md"),
    "json": ("application/json", "json"),
    "csv": ("text/csv; charset=utf-8", "csv"),
    "pdf": ("application/pdf", "pdf"),
}


class ResultsService:
    def __init__(
        self,
        database: Database,
        *,
        audit: AuditService | None = None,
        limiter: RateLimiter | None = None,
        settings: ReportSettings | None = None,
    ) -> None:
        self._db = database
        self._audit = audit
        self._limiter = limiter
        self._settings = settings or ReportSettings()

    async def _job(self, session: Any, access: ProjectAccess, job_id: UUID) -> ResearchJob:
        job: ResearchJob | None = (
            await session.execute(
                select(ResearchJob).where(
                    ResearchJob.organization_id == access.org.organization_id,
                    ResearchJob.project_id == access.project_id,
                    ResearchJob.id == job_id,
                )
            )
        ).scalar_one_or_none()
        if job is None:
            raise NotFound
        return job

    @staticmethod
    def _require_origins(access: ProjectAccess, job: ResearchJob) -> None:
        missing = [p.value for p in MODE_READ.get(job.mode, ()) if not access.can(p)]
        if missing:
            raise PermissionDenied(
                f"Reading this job's results needs these permissions: {', '.join(missing)}."
            )

    # ------------------------------------------------------------------------------ plan
    async def plan(self, access: ProjectAccess, job_id: UUID) -> ResearchPlanResponse:
        access.require(Permission.RESEARCH_READ)
        async with self._db.tenant(access.scope, read_only=True) as session:
            job = await self._job(session, access, job_id)
            row = (
                await session.execute(
                    select(ResearchPlan)
                    .where(
                        ResearchPlan.organization_id == job.organization_id,
                        ResearchPlan.job_id == job.id,
                    )
                    .order_by(ResearchPlan.version.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
        if row is None:
            raise NotFound("This job has no plan yet.")
        plan = row.plan or {}
        return ResearchPlanResponse(
            version=row.version,
            summary=str(plan.get("summary", "")),
            questions=list(plan.get("questions", [])),
            out_of_scope=[str(item) for item in plan.get("out_of_scope", [])],
            model=row.model,
            prompt_version=row.prompt_version,
            created_at=row.created_at,
        )

    # -------------------------------------------------------------------------- findings
    async def findings(self, access: ProjectAccess, job_id: UUID) -> FindingsResponse:
        access.require(Permission.RESEARCH_READ)
        ceiling = int(access.classification_ceiling)
        async with self._db.tenant(access.scope, read_only=True) as session:
            job = await self._job(session, access, job_id)
            self._require_origins(access, job)
            findings = (
                (
                    await session.execute(
                        select(ResearchFinding)
                        .where(
                            ResearchFinding.organization_id == job.organization_id,
                            ResearchFinding.job_id == job.id,
                        )
                        .order_by(
                            func.length(ResearchFinding.question_id),
                            ResearchFinding.question_id,
                            ResearchFinding.ordinal,
                        )
                    )
                )
                .scalars()
                .all()
            )
            citations: dict[UUID, list[Any]] = defaultdict(list)
            contested: set[UUID] = set()
            if findings:
                for a, b in await session.execute(
                    select(
                        ResearchContradiction.finding_a_id, ResearchContradiction.finding_b_id
                    ).where(
                        ResearchContradiction.organization_id == job.organization_id,
                        ResearchContradiction.job_id == job.id,
                    )
                ):
                    contested.update((a, b))
                cited = await session.execute(
                    select(
                        ResearchCitation,
                        DocumentChunk.origin,
                        DocumentChunk.classification,
                        DocumentChunk.document_id,
                        DocumentChunk.source_id,
                        DocumentChunk.title,
                        DocumentChunk.page_start,
                        DocumentChunk.page_end,
                        Source.url,
                        Document.filename,
                    )
                    .join(DocumentChunk, DocumentChunk.id == ResearchCitation.chunk_id)
                    .outerjoin(Source, Source.id == DocumentChunk.source_id)
                    .outerjoin(Document, Document.id == DocumentChunk.document_id)
                    .where(
                        ResearchCitation.organization_id == job.organization_id,
                        ResearchCitation.finding_id.in_([f.id for f in findings]),
                    )
                    .order_by(  # E2 before E10
                        ResearchCitation.finding_id,
                        func.length(ResearchCitation.ref),
                        ResearchCitation.ref,
                    )
                )
                for row in cited:
                    citations[row.ResearchCitation.finding_id].append(row)

        views: list[FindingView] = []
        withheld = 0
        for finding in findings:
            rows = citations.get(finding.id, [])
            verified = finding.verified and any(row.ResearchCitation.verified for row in rows)
            evidence_level = max(
                [finding.evidence_classification, *(row.classification for row in rows)]
            )
            if evidence_level > ceiling:
                withheld += 1
                views.append(
                    FindingView(
                        id=finding.id,
                        question_id=finding.question_id,
                        ordinal=finding.ordinal,
                        withheld=True,
                        statement=None,
                        kind=finding.kind,
                        confidence=finding.confidence,
                        verified=verified,
                        support=finding.support,
                        support_rationale=None,
                        contested=finding.id in contested,
                        model=finding.model,
                        agent_run_id=finding.agent_run_id,
                        citations=[],
                        hidden_citations=len(rows),
                        created_at=finding.created_at,
                    )
                )
                continue
            visible = [row for row in rows if self._can_see(access, row, ceiling)]
            views.append(
                FindingView(
                    id=finding.id,
                    question_id=finding.question_id,
                    ordinal=finding.ordinal,
                    withheld=False,
                    statement=finding.statement,
                    kind=finding.kind,
                    confidence=finding.confidence,
                    verified=verified,
                    support=finding.support,
                    support_rationale=finding.support_rationale,
                    contested=finding.id in contested,
                    model=finding.model,
                    agent_run_id=finding.agent_run_id,
                    citations=[self._citation(row) for row in visible],
                    hidden_citations=len(rows) - len(visible),
                    created_at=finding.created_at,
                )
            )
        return FindingsResponse(job_id=job_id, findings=views, withheld=withheld)

    @staticmethod
    def _can_see(access: ProjectAccess, row: Any, ceiling: int) -> bool:
        permission = _ORIGIN_PERMISSION.get(row.origin)
        return permission is not None and access.can(permission) and row.classification <= ceiling

    @staticmethod
    def _citation(row: Any) -> CitationView:
        citation: ResearchCitation = row.ResearchCitation
        return CitationView(
            ref=citation.ref,
            quote=citation.quote,
            verified=citation.verified,
            chunk_id=citation.chunk_id,
            origin=row.origin,
            document_id=row.document_id,
            source_id=row.source_id,
            title=row.title,
            url=row.url,
            filename=row.filename,
            page_start=row.page_start,
            page_end=row.page_end,
        )

    # ------------------------------------------------------------------------ agent trail
    async def agent_runs(self, access: ProjectAccess, job_id: UUID) -> list[AgentRunView]:
        access.require(Permission.RESEARCH_READ)
        ceiling = int(access.classification_ceiling)
        async with self._db.tenant(access.scope, read_only=True) as session:
            job = await self._job(session, access, job_id)
            self._require_origins(access, job)
            runs = (
                (
                    await session.execute(
                        select(AgentRun)
                        .where(
                            AgentRun.organization_id == job.organization_id,
                            AgentRun.job_id == job.id,
                        )
                        .order_by(AgentRun.created_at, AgentRun.id)
                    )
                )
                .scalars()
                .all()
            )
            calls: dict[UUID, list[ToolCallRecord]] = defaultdict(list)
            if runs:
                for call in (
                    await session.execute(
                        select(ToolCallRecord)
                        .where(
                            ToolCallRecord.organization_id == job.organization_id,
                            ToolCallRecord.agent_run_id.in_([run.id for run in runs]),
                        )
                        .order_by(ToolCallRecord.created_at, ToolCallRecord.id)
                    )
                ).scalars():
                    calls[call.agent_run_id].append(call)
        views: list[AgentRunView] = []
        for run in runs:
            details = run.details or {}
            redacted = int(details.get("evidence_classification", 0)) > ceiling
            views.append(
                AgentRunView(
                    id=run.id,
                    agent=run.agent,
                    status=run.status,
                    iterations=run.iterations,
                    tool_calls=run.tool_calls,
                    cost_usd=run.cost_usd,
                    models=[str(m) for m in details.get("models", [])],
                    prompts=[str(p) for p in details.get("prompts", [])],
                    redacted=redacted,
                    calls=[
                        ToolCallView(
                            id=call.id,
                            tool=call.tool,
                            outcome=call.outcome,
                            arguments=None if redacted else call.arguments,
                            result=None if redacted else call.result,
                            latency_ms=call.latency_ms,
                            created_at=call.created_at,
                        )
                        for call in calls.get(run.id, [])
                    ],
                    created_at=run.created_at,
                    finished_at=run.finished_at,
                )
            )
        return views

    # --------------------------------------------------------------------- contradictions
    async def contradictions(self, access: ProjectAccess, job_id: UUID) -> ContradictionsResponse:
        access.require(Permission.RESEARCH_READ)
        ceiling = int(access.classification_ceiling)
        async with self._db.tenant(access.scope, read_only=True) as session:
            job = await self._job(session, access, job_id)
            self._require_origins(access, job)
            rows = (
                (
                    await session.execute(
                        select(ResearchContradiction)
                        .where(
                            ResearchContradiction.organization_id == job.organization_id,
                            ResearchContradiction.job_id == job.id,
                        )
                        .order_by(ResearchContradiction.created_at, ResearchContradiction.id)
                    )
                )
                .scalars()
                .all()
            )
            levels = await self._finding_levels(
                session,
                job,
                {row.finding_a_id for row in rows} | {row.finding_b_id for row in rows},
            )
        views: list[ContradictionView] = []
        withheld = 0
        for row in rows:
            hidden = max(levels.get(row.finding_a_id, 3), levels.get(row.finding_b_id, 3)) > ceiling
            withheld += int(hidden)
            views.append(
                ContradictionView(
                    id=row.id,
                    finding_a_id=row.finding_a_id,
                    finding_b_id=row.finding_b_id,
                    withheld=hidden,
                    attribute=None if hidden else row.attribute,
                    explanation=None if hidden else row.explanation,
                    rationale=None if hidden else row.rationale,
                    preferred=None if hidden else row.preferred,
                    created_at=row.created_at,
                )
            )
        return ContradictionsResponse(job_id=job_id, contradictions=views, withheld=withheld)

    @staticmethod
    async def _finding_levels(
        session: Any, job: ResearchJob, finding_ids: set[UUID]
    ) -> dict[UUID, int]:
        """Highest classification behind each finding: what its analyst read or it cites."""
        if not finding_ids:
            return {}
        levels = {
            row.id: row.evidence_classification
            for row in await session.execute(
                select(ResearchFinding.id, ResearchFinding.evidence_classification).where(
                    ResearchFinding.organization_id == job.organization_id,
                    ResearchFinding.id.in_(finding_ids),
                )
            )
        }
        for finding_id, level in await session.execute(
            select(ResearchCitation.finding_id, func.max(DocumentChunk.classification))
            .join(DocumentChunk, DocumentChunk.id == ResearchCitation.chunk_id)
            .where(
                ResearchCitation.organization_id == job.organization_id,
                ResearchCitation.finding_id.in_(finding_ids),
            )
            .group_by(ResearchCitation.finding_id)
        ):
            levels[finding_id] = max(levels.get(finding_id, 0), int(level))
        return levels

    # ---------------------------------------------------------------------------- report
    async def _report(
        self, access: ProjectAccess, job_id: UUID, permission: Permission
    ) -> tuple[ResearchJob, ResearchReport]:
        access.require(permission)
        async with self._db.tenant(access.scope, read_only=True) as session:
            job = await self._job(session, access, job_id)
            self._require_origins(access, job)
            report = (
                await session.execute(
                    select(ResearchReport)
                    .where(
                        ResearchReport.organization_id == job.organization_id,
                        ResearchReport.job_id == job.id,
                    )
                    .order_by(ResearchReport.version.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
        if report is None:
            raise NotFound("This job has no report yet.")
        if report.evidence_classification > int(access.classification_ceiling):
            # A summary blends every finding; it cannot be filtered per statement.
            raise PermissionDenied(
                "This report rests on evidence above your clearance. Ask an administrator."
            )
        return job, report

    async def report(self, access: ProjectAccess, job_id: UUID) -> ReportDocument:
        _, report = await self._report(access, job_id, Permission.REPORTS_READ)
        return ReportDocument.model_validate(report.content)

    async def export(
        self, access: ProjectAccess, job_id: UUID, fmt: ExportFormat, client: ClientInfo
    ) -> Export:
        if self._limiter is not None:
            principal = access.org.principal
            key = str(principal.api_key_id or principal.user_id or principal.service_account_id)
            decision = await self._limiter.hit(POLICIES["reports.export.user"], key)
            if not decision.allowed:
                raise RateLimited(decision.retry_after_s)
        job, report = await self._report(access, job_id, Permission.REPORTS_EXPORT)
        document = ReportDocument.model_validate(report.content)
        if fmt == "markdown":
            content = render_markdown(document).encode("utf-8")
        elif fmt == "json":
            content = render_json(document).encode("utf-8")
        elif fmt == "csv":
            content = ("\ufeff" + render_csv(document)).encode("utf-8")  # BOM: Excel reads UTF-8
        else:
            content = render_pdf(document, font_path=self._settings.pdf_font_path)
        media_type, extension = _MEDIA[fmt]
        if self._audit is not None:
            async with self._db.tenant(access.scope) as session:
                await self._audit.record(
                    session,
                    AuditEvent(
                        action="report.exported",
                        category=AuditCategory.DATA_ACCESS,
                        actor=access.scope.actor,
                        organization_id=job.organization_id,
                        target_type="research_job",
                        target_id=str(job.id),
                        client=client,
                        details={"format": fmt, "version": report.version, "bytes": len(content)},
                    ),
                )
        return Export(content, media_type, f"argus-report-{job.id}-v{report.version}.{extension}")
