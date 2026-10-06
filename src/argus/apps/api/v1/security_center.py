"""/api/v1/orgs/{org_id}/security - the security centre for organisation administrators."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from argus.apps.api.access import org_access
from argus.apps.api.security import ClientDep, ContainerDep
from argus.core.errors import ValidationFailed
from argus.core.pagination import Page
from argus.modules.security_center.schemas import (
    AuditVerificationResponse,
    EngageKillSwitchRequest,
    KillSwitchResponse,
    SecuritySummary,
)
from argus.modules.tenancy.authorization import OrgAccess
from argus.modules.tenancy.schemas import AuditLogEntry
from argus.security.permissions import Permission

router = APIRouter(tags=["security"])
BASE = "/orgs/{org_id}/security"
ReadAccess = Annotated[OrgAccess, Depends(org_access(Permission.AUDIT_READ))]
ManageAccess = Annotated[OrgAccess, Depends(org_access(Permission.SECURITY_MANAGE))]


@router.get(BASE + "/summary", response_model=SecuritySummary)
async def security_summary(
    access: ReadAccess,
    container: ContainerDep,
    days: Annotated[int, Query(ge=1, le=90)] = 7,
) -> SecuritySummary:
    return await container.security.summary(access, days=days)


@router.get(BASE + "/events", response_model=Page[AuditLogEntry])
async def security_events(
    access: ReadAccess,
    container: ContainerDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Annotated[str | None, Query(max_length=20, pattern=r"^\d+$")] = None,
) -> Page[AuditLogEntry]:
    """Denied and failed actions plus authentication, authorisation and security events."""
    before = int(cursor) if cursor else None
    if before is not None and before > 2**62:
        raise ValidationFailed("The pagination cursor is invalid.")
    rows = await container.security.events(access, limit=limit + 1, before_id=before)
    next_cursor = str(rows[limit - 1].id) if len(rows) > limit else None
    return Page[AuditLogEntry](
        items=[AuditLogEntry.model_validate(row) for row in rows[:limit]], next_cursor=next_cursor
    )


# ----------------------------------------------------------------------------- kill switches
@router.get(BASE + "/kill-switches", response_model=list[KillSwitchResponse])
async def list_kill_switches(
    access: ReadAccess,
    container: ContainerDep,
    include_inactive: Annotated[bool, Query()] = False,
) -> list[KillSwitchResponse]:
    return await container.security.list_switches(access, include_inactive=include_inactive)


@router.post(
    BASE + "/kill-switches",
    status_code=status.HTTP_201_CREATED,
    response_model=KillSwitchResponse,
)
async def engage_kill_switch(
    body: EngageKillSwitchRequest,
    access: ManageAccess,
    container: ContainerDep,
    client: ClientDep,
) -> KillSwitchResponse:
    return await container.security.engage(access, body, client)


@router.delete(BASE + "/kill-switches/{switch_id}", status_code=status.HTTP_204_NO_CONTENT)
async def release_kill_switch(
    switch_id: UUID,
    access: ManageAccess,
    container: ContainerDep,
    client: ClientDep,
) -> Response:
    await container.security.release(access, switch_id, client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- audit integrity
@router.get(BASE + "/audit-verifications", response_model=list[AuditVerificationResponse])
async def list_audit_verifications(
    access: ReadAccess,
    container: ContainerDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[AuditVerificationResponse]:
    return await container.security.verifications(access, limit=limit)


@router.post(
    BASE + "/audit-verifications",
    status_code=status.HTTP_201_CREATED,
    response_model=AuditVerificationResponse,
)
async def verify_audit_log(
    access: ManageAccess, container: ContainerDep
) -> AuditVerificationResponse:
    """Verify this organisation's audit chain now (rate-limited; it reads the whole chain)."""
    return await container.security.verify_now(access)
