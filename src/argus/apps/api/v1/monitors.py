"""/api/v1 monitors and the changes they detect."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from argus.apps.api.access import project_access
from argus.apps.api.deps import PageDep
from argus.apps.api.security import ClientDep, ContainerDep
from argus.core.pagination import Page
from argus.modules.monitoring.schemas import (
    ChangeDecisionRequest,
    CreateMonitorRequest,
    MonitorChangeResponse,
    MonitorResponse,
    UpdateMonitorRequest,
)
from argus.modules.tenancy.authorization import ProjectAccess
from argus.security.permissions import Permission

router = APIRouter(tags=["monitors"])
P = Permission
BASE = "/orgs/{org_id}/projects/{project_id}/monitors"


@router.post(BASE, status_code=status.HTTP_201_CREATED, response_model=MonitorResponse)
async def create_monitor(
    body: CreateMonitorRequest,
    access: Annotated[ProjectAccess, Depends(project_access(P.MONITORS_MANAGE))],
    container: ContainerDep,
    client: ClientDep,
) -> MonitorResponse:
    return await container.monitors.create(access, body, client)


@router.get(BASE, response_model=Page[MonitorResponse])
async def list_monitors(
    access: Annotated[ProjectAccess, Depends(project_access(P.MONITORS_READ))],
    container: ContainerDep,
    page: PageDep,
) -> Page[MonitorResponse]:
    return await container.monitors.list_monitors(access, page)


@router.get(BASE + "/{monitor_id}", response_model=MonitorResponse)
async def get_monitor(
    monitor_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.MONITORS_READ))],
    container: ContainerDep,
) -> MonitorResponse:
    return await container.monitors.get(access, monitor_id)


@router.patch(BASE + "/{monitor_id}", response_model=MonitorResponse)
async def update_monitor(
    monitor_id: UUID,
    body: UpdateMonitorRequest,
    access: Annotated[ProjectAccess, Depends(project_access(P.MONITORS_MANAGE))],
    container: ContainerDep,
    client: ClientDep,
) -> MonitorResponse:
    return await container.monitors.update(access, monitor_id, body, client)


@router.delete(BASE + "/{monitor_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_monitor(
    monitor_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.MONITORS_MANAGE))],
    container: ContainerDep,
    client: ClientDep,
) -> Response:
    await container.monitors.delete(access, monitor_id, client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(BASE + "/{monitor_id}/run", status_code=status.HTTP_202_ACCEPTED)
async def run_monitor(
    monitor_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.MONITORS_MANAGE))],
    container: ContainerDep,
    client: ClientDep,
) -> Response:
    await container.monitors.run_now(access, monitor_id, client)
    return Response(status_code=status.HTTP_202_ACCEPTED)


@router.get(BASE + "/{monitor_id}/changes", response_model=Page[MonitorChangeResponse])
async def list_changes(
    monitor_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.MONITORS_READ))],
    container: ContainerDep,
    page: PageDep,
    status_filter: Annotated[
        Literal["new", "acknowledged", "dismissed"] | None, Query(alias="status")
    ] = None,
) -> Page[MonitorChangeResponse]:
    return await container.monitors.changes(access, monitor_id, page, status=status_filter)


@router.post(
    BASE + "/{monitor_id}/changes/{change_id}/decision", response_model=MonitorChangeResponse
)
async def decide_change(
    monitor_id: UUID,
    change_id: UUID,
    body: ChangeDecisionRequest,
    access: Annotated[ProjectAccess, Depends(project_access(P.MONITORS_MANAGE))],
    container: ContainerDep,
    client: ClientDep,
) -> MonitorChangeResponse:
    return await container.monitors.decide_change(
        access, monitor_id, change_id, body.status, client
    )
