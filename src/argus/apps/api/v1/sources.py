"""/api/v1 sources and domain policies."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Response, status

from argus.apps.api.access import org_access, project_access
from argus.apps.api.deps import PageDep
from argus.apps.api.security import ClientDep, ContainerDep
from argus.core.pagination import Page
from argus.modules.sources.schemas import (
    AddSourceRequest,
    DomainName,
    DomainPolicyRequest,
    DomainPolicyResponse,
    SnapshotSummary,
    SourceDetail,
    SourceResponse,
)
from argus.modules.tenancy.authorization import OrgAccess, ProjectAccess
from argus.security.permissions import Permission

router = APIRouter(tags=["sources"])
P = Permission
BASE = "/orgs/{org_id}/projects/{project_id}/sources"


@router.post(BASE, status_code=status.HTTP_202_ACCEPTED, response_model=SourceResponse)
async def add_source(
    body: AddSourceRequest,
    access: Annotated[ProjectAccess, Depends(project_access(P.SOURCES_MANAGE))],
    container: ContainerDep,
    client: ClientDep,
) -> SourceResponse:
    return await container.sources.add(access, body.url, client)


@router.get(BASE, response_model=Page[SourceResponse])
async def list_sources(
    access: Annotated[ProjectAccess, Depends(project_access(P.SOURCES_READ))],
    container: ContainerDep,
    page: PageDep,
) -> Page[SourceResponse]:
    return await container.sources.list_sources(access, page)


@router.get(BASE + "/{source_id}", response_model=SourceDetail)
async def get_source(
    source_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.SOURCES_READ))],
    container: ContainerDep,
) -> SourceDetail:
    return await container.sources.get(access, source_id)


@router.get(BASE + "/{source_id}/snapshots", response_model=list[SnapshotSummary])
async def list_snapshots(
    source_id: UUID,
    access: Annotated[ProjectAccess, Depends(project_access(P.SOURCES_READ))],
    container: ContainerDep,
) -> list[SnapshotSummary]:
    return await container.sources.snapshots(access, source_id)


@router.get("/orgs/{org_id}/domain-policies", response_model=list[DomainPolicyResponse])
async def list_domain_policies(
    access: Annotated[OrgAccess, Depends(org_access(P.SOURCES_READ))], container: ContainerDep
) -> list[DomainPolicyResponse]:
    return await container.sources.list_policies(access)


@router.put("/orgs/{org_id}/domain-policies/{domain}", response_model=DomainPolicyResponse)
async def set_domain_policy(
    domain: Annotated[DomainName, Path(max_length=253)],
    body: DomainPolicyRequest,
    access: Annotated[OrgAccess, Depends(org_access(P.SOURCES_MANAGE))],
    container: ContainerDep,
    client: ClientDep,
) -> DomainPolicyResponse:
    return await container.sources.set_policy(access, domain, body, client)


@router.delete("/orgs/{org_id}/domain-policies/{domain}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_domain_policy(
    domain: Annotated[DomainName, Path(max_length=253)],
    access: Annotated[OrgAccess, Depends(org_access(P.SOURCES_MANAGE))],
    container: ContainerDep,
    client: ClientDep,
) -> Response:
    await container.sources.delete_policy(access, domain, client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
