"""/api/v1 in-app notifications (always the caller's own)."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from argus.apps.api.access import org_access
from argus.apps.api.deps import PageDep
from argus.apps.api.security import ContainerDep
from argus.core.pagination import Page
from argus.modules.notifications.schemas import NotificationResponse, UnreadCountResponse
from argus.modules.tenancy.authorization import OrgAccess
from argus.security.permissions import Permission

router = APIRouter(tags=["notifications"])
BASE = "/orgs/{org_id}/notifications"


@router.get(BASE, response_model=Page[NotificationResponse])
async def list_notifications(
    access: Annotated[OrgAccess, Depends(org_access(Permission.ORG_READ))],
    container: ContainerDep,
    page: PageDep,
    unread: Annotated[bool, Query()] = False,
) -> Page[NotificationResponse]:
    return await container.notifications.list_notifications(access, page, unread=unread)


@router.get(BASE + "/unread-count", response_model=UnreadCountResponse)
async def unread_count(
    access: Annotated[OrgAccess, Depends(org_access(Permission.ORG_READ))],
    container: ContainerDep,
) -> UnreadCountResponse:
    return await container.notifications.unread_count(access)


@router.post(BASE + "/{notification_id}/read", status_code=status.HTTP_204_NO_CONTENT)
async def mark_read(
    notification_id: UUID,
    access: Annotated[OrgAccess, Depends(org_access(Permission.ORG_READ))],
    container: ContainerDep,
) -> Response:
    await container.notifications.mark_read(access, notification_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(BASE + "/read-all", status_code=status.HTTP_204_NO_CONTENT)
async def mark_all_read(
    access: Annotated[OrgAccess, Depends(org_access(Permission.ORG_READ))],
    container: ContainerDep,
) -> Response:
    await container.notifications.mark_all_read(access)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
