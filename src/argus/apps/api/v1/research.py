"""/api/v1/orgs/{org_id}/projects/{project_id}/research-jobs and approvals."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import JSONResponse, Response

from argus.apps.api.access import org_access, project_access
from argus.apps.api.deps import PageDep
from argus.apps.api.security import ClientDep, ContainerDep
from argus.core.pagination import Page
from argus.modules.research.report_model import ReportDocument
from argus.modules.research.schemas import (
    AgentRunView,
    ApprovalDecisionRequest,
    ApprovalResponse,
    ContradictionsResponse,
    CreateResearchJobRequest,
    FindingsResponse,
    ResearchJobResponse,
    ResearchPlanResponse,
    ResearchStepResponse,
)
from argus.modules.tenancy.authorization import OrgAccess, ProjectAccess
from argus.security.permissions import Permission

router = APIRouter(tags=["research"])
P = Permission
BASE = "/orgs/{org_id}/projects/{project_id}/research-jobs"
JobStatus = Literal["queued", "running", "awaiting_approval", "completed", "failed", "cancelled"]


@router.post(BASE, status_code=202, response_model=ResearchJobResponse)
async def create_research_job(
    request: Request,
    body: CreateResearchJobRequest,
    access: Annotated[ProjectAccess, Depends(project_access(P.RESEARCH_CREATE))],
    container: ContainerDep,
    client: ClientDep,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", max_length=128)] = None,
) -> JSONResponse:
    created = await container.research.create(
        access, body, client, idempotency_key=idempotency_key, path=request.url.path
    )
    headers = {}
    job_id = created.body.get("id")
    if job_id:
        headers["Location"] = f"{request.url.path}/{job_id}"
    if created.job_id is None:
        headers["Idempotent-Replayed"] = "true"
    return JSONResponse(created.body, status_code=created.status, headers=headers)


@router.get(BASE, response_model=Page[ResearchJobResponse])
async def list_research_jobs(
    access: Annotated[ProjectAccess, Depends(project_access(P.RESEARCH_READ))],
    container: ContainerDep,
    page: PageDep,
    status: Annotated[JobStatus | None, Query()] = None,
) -> Page[ResearchJobResponse]:
    return await container.research.list_jobs(access, page, status)


@router.get(BASE + "/{job_id}", response_model=ResearchJobResponse)
async def get_research_job(
    job_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.RESEARCH_READ))],
    container: ContainerDep,
) -> ResearchJobResponse:
    return await container.research.get(access, job_id)


@router.get(BASE + "/{job_id}/steps", response_model=list[ResearchStepResponse])
async def get_research_steps(
    job_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.RESEARCH_READ))],
    container: ContainerDep,
) -> list[ResearchStepResponse]:
    return await container.research.steps(access, job_id)


@router.get(BASE + "/{job_id}/plan", response_model=ResearchPlanResponse)
async def get_research_plan(
    job_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.RESEARCH_READ))],
    container: ContainerDep,
) -> ResearchPlanResponse:
    return await container.results.plan(access, job_id)


@router.get(BASE + "/{job_id}/findings", response_model=FindingsResponse)
async def get_research_findings(
    job_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.RESEARCH_READ))],
    container: ContainerDep,
) -> FindingsResponse:
    return await container.results.findings(access, job_id)


@router.get(BASE + "/{job_id}/agent-runs", response_model=list[AgentRunView])
async def get_research_agent_runs(
    job_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.RESEARCH_READ))],
    container: ContainerDep,
) -> list[AgentRunView]:
    return await container.results.agent_runs(access, job_id)


@router.get(BASE + "/{job_id}/contradictions", response_model=ContradictionsResponse)
async def get_research_contradictions(
    job_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.RESEARCH_READ))],
    container: ContainerDep,
) -> ContradictionsResponse:
    return await container.results.contradictions(access, job_id)


@router.get(BASE + "/{job_id}/report", response_model=ReportDocument)
async def get_research_report(
    job_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.REPORTS_READ))],
    container: ContainerDep,
) -> ReportDocument:
    return await container.results.report(access, job_id)


@router.get(BASE + "/{job_id}/report/export")
async def export_research_report(
    job_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.REPORTS_EXPORT))],
    container: ContainerDep,
    client: ClientDep,
    format: Annotated[Literal["markdown", "json", "csv", "pdf"], Query()] = "markdown",
) -> Response:
    export = await container.results.export(access, job_id, format, client)
    return Response(
        export.content,
        media_type=export.media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{export.filename}"',
            "Cache-Control": "no-store",
        },
    )


@router.post(BASE + "/{job_id}/cancel", response_model=ResearchJobResponse)
async def cancel_research_job(
    job_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.RESEARCH_CANCEL))],
    container: ContainerDep,
    client: ClientDep,
) -> ResearchJobResponse:
    return await container.research.cancel(access, job_id, client)


@router.get("/orgs/{org_id}/approvals", response_model=list[ApprovalResponse])
async def list_approvals(
    access: Annotated[OrgAccess, Depends(org_access(P.APPROVALS_DECIDE))],
    container: ContainerDep,
    status: Annotated[Literal["pending", "approved", "rejected", "expired"] | None, Query()] = None,
) -> list[ApprovalResponse]:
    return await container.research.list_approvals(access, status)


@router.post("/orgs/{org_id}/approvals/{approval_id}/decision", response_model=ApprovalResponse)
async def decide_approval(
    approval_id: UUID,
    body: ApprovalDecisionRequest,
    access: Annotated[OrgAccess, Depends(org_access(P.APPROVALS_DECIDE))],
    container: ContainerDep,
    client: ClientDep,
) -> ApprovalResponse:
    return await container.research.decide(
        access, approval_id, approve=body.approve, note=body.note, client=client
    )
