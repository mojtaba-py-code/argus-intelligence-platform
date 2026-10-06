"""/api/v1/orgs/{org_id}: plan usage, the dashboard overview and data exports."""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Response, status

from argus.apps.api.access import org_access
from argus.apps.api.routes.health import readiness_checks
from argus.apps.api.security import ClientDep, ContainerDep
from argus.modules.platform import quotas
from argus.modules.platform.dashboard import DashboardOverview
from argus.modules.platform.exports import ExportResponse
from argus.modules.tenancy.authorization import OrgAccess
from argus.security.permissions import Permission

router = APIRouter(tags=["platform"])
BASE = "/orgs/{org_id}"


@router.get(BASE + "/usage")
async def usage(
    access: Annotated[OrgAccess, Depends(org_access(Permission.USAGE_READ))],
    container: ContainerDep,
) -> dict[str, Any]:
    """The organisation's plan, its limits and current usage, and this month's model spend."""
    async with container.database.tenant(access.scope, read_only=True) as session:
        return await quotas.report(
            session,
            access.organization_id,
            now=container.clock.now(),
            organization_budget=access.settings.budgets.monthly_llm_usd,
        )


@router.get(BASE + "/dashboard")
async def dashboard(
    access: Annotated[OrgAccess, Depends(org_access(Permission.ORG_READ))],
    container: ContainerDep,
) -> dict[str, Any]:
    overview: DashboardOverview = await container.dashboard.overview(access)
    body: dict[str, Any] = overview.model_dump(mode="json")
    body["system"] = await readiness_checks(container)
    if access.can(Permission.AUDIT_READ):
        summary = await container.security.summary(access, days=7)
        body["security"] = {
            "denied": summary.access.denied,
            "tool_denials": summary.agents.tool_denials,
            "injection_high": summary.content.injection_high,
            "blocked_egress": summary.egress.blocked,
            "active_kill_switches": sum(1 for s in summary.kill_switches if s.active),
            "audit_valid": summary.last_audit_verification.valid
            if summary.last_audit_verification
            else None,
            "recommendations": [r.model_dump() for r in summary.recommendations[:5]],
            "recommendation_count": len(summary.recommendations),
        }
    else:
        body["security"] = None
    return body


@router.post(BASE + "/exports", status_code=status.HTTP_202_ACCEPTED, response_model=ExportResponse)
async def request_export(
    access: Annotated[OrgAccess, Depends(org_access(Permission.ORG_EXPORT))],
    container: ContainerDep,
    client: ClientDep,
) -> ExportResponse:
    return await container.exports.request(access, client)


@router.get(BASE + "/exports", response_model=list[ExportResponse])
async def list_exports(
    access: Annotated[OrgAccess, Depends(org_access(Permission.ORG_EXPORT))],
    container: ContainerDep,
) -> list[ExportResponse]:
    return await container.exports.list(access)


@router.get(BASE + "/exports/{export_id}/download")
async def download_export(
    export_id: UUID,
    access: Annotated[OrgAccess, Depends(org_access(Permission.ORG_EXPORT))],
    container: ContainerDep,
    client: ClientDep,
) -> Response:
    download = await container.exports.download(access, export_id, client)
    return Response(
        content=download.content,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{download.filename}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
