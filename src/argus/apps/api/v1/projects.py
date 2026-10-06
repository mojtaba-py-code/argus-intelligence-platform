"""/api/v1/orgs/{org_id}/projects - research workspaces and project membership."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Response, status

from argus.apps.api.access import org_access, project_access
from argus.apps.api.deps import PageDep
from argus.apps.api.security import ClientDep, ContainerDep
from argus.core.pagination import Page
from argus.modules.tenancy.authorization import OrgAccess, ProjectAccess
from argus.modules.tenancy.schemas import (
    CreateProjectRequest,
    ProjectMemberRequest,
    ProjectMemberResponse,
    ProjectResponse,
    UpdateProjectRequest,
)
from argus.security.permissions import Permission

router = APIRouter(prefix="/orgs/{org_id}/projects", tags=["projects"])
P = Permission


@router.post("", status_code=status.HTTP_201_CREATED, response_model=ProjectResponse)
async def create_project(
    body: CreateProjectRequest,
    access: Annotated[OrgAccess, Depends(org_access(P.PROJECTS_CREATE))],
    container: ContainerDep,
    client: ClientDep,
) -> ProjectResponse:
    return await container.projects.create(access, body, client)


@router.get("", response_model=Page[ProjectResponse])
async def list_projects(
    access: Annotated[OrgAccess, Depends(org_access(P.PROJECTS_READ))],
    container: ContainerDep,
    page: PageDep,
) -> Page[ProjectResponse]:
    return await container.projects.list_projects(access, page)


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    access: Annotated[ProjectAccess, Depends(project_access(P.PROJECTS_READ))],
) -> ProjectResponse:
    return ProjectResponse.model_validate(access.project)


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(
    body: UpdateProjectRequest,
    access: Annotated[ProjectAccess, Depends(project_access(P.PROJECTS_UPDATE))],
    container: ContainerDep,
    client: ClientDep,
) -> ProjectResponse:
    return await container.projects.update(access, body, client)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    access: Annotated[ProjectAccess, Depends(project_access(P.PROJECTS_READ))],
    container: ContainerDep,
    client: ClientDep,
) -> Response:
    await container.projects.delete(access, client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{project_id}/members", response_model=list[ProjectMemberResponse])
async def list_project_members(
    access: Annotated[ProjectAccess, Depends(project_access(P.PROJECTS_READ))],
    container: ContainerDep,
) -> list[ProjectMemberResponse]:
    return await container.projects.list_members(access)


@router.put("/{project_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def set_project_member(
    user_id: UUID,
    body: ProjectMemberRequest,
    access: Annotated[ProjectAccess, Depends(project_access(P.PROJECTS_READ))],
    container: ContainerDep,
    client: ClientDep,
) -> Response:
    await container.projects.set_member(access, user_id, body.role, client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/{project_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_project_member(
    user_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.PROJECTS_READ))],
    container: ContainerDep,
    client: ClientDep,
) -> Response:
    await container.projects.remove_member(access, user_id, client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
