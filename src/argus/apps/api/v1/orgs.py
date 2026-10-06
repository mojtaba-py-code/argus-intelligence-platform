"""/api/v1/orgs - organisations, members, invitations, service accounts, API keys, audit log."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from argus.apps.api.access import org_access
from argus.apps.api.security import ClientDep, ContainerDep, PrincipalDep, UserDep
from argus.core.errors import ValidationFailed
from argus.core.pagination import Page
from argus.modules.tenancy.authorization import OrgAccess
from argus.modules.tenancy.schemas import (
    AcceptInvitationRequest,
    ApiKeyResponse,
    AuditLogEntry,
    ChangeRoleRequest,
    CreateApiKeyRequest,
    CreatedApiKeyResponse,
    CreateInvitationRequest,
    CreateOrganizationRequest,
    CreateServiceAccountRequest,
    InvitationResponse,
    MemberResponse,
    OrganizationResponse,
    ServiceAccountResponse,
    UpdateOrganizationRequest,
)
from argus.security.permissions import Permission

router = APIRouter(tags=["organizations"])
P = Permission


@router.post("/orgs", status_code=status.HTTP_201_CREATED, response_model=OrganizationResponse)
async def create_organization(
    body: CreateOrganizationRequest, principal: UserDep, container: ContainerDep, client: ClientDep
) -> OrganizationResponse:
    return await container.organizations.create(principal, body, client)


@router.get("/orgs", response_model=list[OrganizationResponse])
async def list_organizations(
    principal: PrincipalDep, container: ContainerDep
) -> list[OrganizationResponse]:
    return await container.organizations.list_mine(principal)


@router.get("/orgs/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    access: Annotated[OrgAccess, Depends(org_access(P.ORG_READ))], container: ContainerDep
) -> OrganizationResponse:
    return await container.organizations.get(access)


@router.patch("/orgs/{org_id}", response_model=OrganizationResponse)
async def update_organization(
    body: UpdateOrganizationRequest,
    access: Annotated[OrgAccess, Depends(org_access(P.ORG_UPDATE))],
    container: ContainerDep,
    client: ClientDep,
) -> OrganizationResponse:
    return await container.organizations.update(access, body, client)


@router.delete("/orgs/{org_id}", status_code=status.HTTP_202_ACCEPTED)
async def delete_organization(
    access: Annotated[OrgAccess, Depends(org_access(P.ORG_DELETE))],
    container: ContainerDep,
    client: ClientDep,
) -> Response:
    await container.organizations.request_deletion(access, client)
    return Response(status_code=status.HTTP_202_ACCEPTED)


# ----------------------------------------------------------------------------- members
@router.get("/orgs/{org_id}/members", response_model=list[MemberResponse])
async def list_members(
    access: Annotated[OrgAccess, Depends(org_access(P.MEMBERS_READ))], container: ContainerDep
) -> list[MemberResponse]:
    return await container.organizations.list_members(access)


@router.patch("/orgs/{org_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def change_member_role(
    user_id: UUID,
    body: ChangeRoleRequest,
    access: Annotated[OrgAccess, Depends(org_access(P.MEMBERS_MANAGE))],
    container: ContainerDep,
    client: ClientDep,
) -> Response:
    await container.organizations.change_role(access, user_id, body.role, client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/orgs/{org_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    user_id: UUID,
    access: Annotated[OrgAccess, Depends(org_access())],
    container: ContainerDep,
    client: ClientDep,
) -> Response:
    if user_id != access.principal.user_id:  # leaving needs no permission; removing others does
        access.require(P.MEMBERS_MANAGE)
    await container.organizations.remove_member(access, user_id, client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ------------------------------------------------------------------------- invitations
@router.post(
    "/orgs/{org_id}/invitations",
    status_code=status.HTTP_201_CREATED,
    response_model=InvitationResponse,
)
async def create_invitation(
    body: CreateInvitationRequest,
    access: Annotated[OrgAccess, Depends(org_access(P.MEMBERS_INVITE))],
    container: ContainerDep,
    client: ClientDep,
) -> InvitationResponse:
    return await container.organizations.invite(access, body, client)


@router.get("/orgs/{org_id}/invitations", response_model=list[InvitationResponse])
async def list_invitations(
    access: Annotated[OrgAccess, Depends(org_access(P.MEMBERS_INVITE))], container: ContainerDep
) -> list[InvitationResponse]:
    return await container.organizations.list_invitations(access)


@router.delete("/orgs/{org_id}/invitations/{invitation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_invitation(
    invitation_id: UUID,
    access: Annotated[OrgAccess, Depends(org_access(P.MEMBERS_INVITE))],
    container: ContainerDep,
    client: ClientDep,
) -> Response:
    await container.organizations.revoke_invitation(access, invitation_id, client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/invitations/accept", response_model=OrganizationResponse)
async def accept_invitation(
    body: AcceptInvitationRequest, principal: UserDep, container: ContainerDep, client: ClientDep
) -> OrganizationResponse:
    return await container.organizations.accept_invitation(principal, body.token, client)


# ------------------------------------------------------------- service accounts & keys
@router.post(
    "/orgs/{org_id}/service-accounts",
    status_code=status.HTTP_201_CREATED,
    response_model=ServiceAccountResponse,
)
async def create_service_account(
    body: CreateServiceAccountRequest,
    access: Annotated[OrgAccess, Depends(org_access(P.SERVICE_ACCOUNTS_MANAGE))],
    container: ContainerDep,
    client: ClientDep,
) -> ServiceAccountResponse:
    return await container.api_keys.create_service_account(access, body, client)


@router.get("/orgs/{org_id}/service-accounts", response_model=list[ServiceAccountResponse])
async def list_service_accounts(
    access: Annotated[OrgAccess, Depends(org_access(P.APIKEYS_READ))], container: ContainerDep
) -> list[ServiceAccountResponse]:
    return await container.api_keys.list_service_accounts(access)


@router.delete(
    "/orgs/{org_id}/service-accounts/{service_account_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def disable_service_account(
    service_account_id: UUID,
    access: Annotated[OrgAccess, Depends(org_access(P.SERVICE_ACCOUNTS_MANAGE))],
    container: ContainerDep,
    client: ClientDep,
) -> Response:
    await container.api_keys.disable_service_account(access, service_account_id, client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/orgs/{org_id}/api-keys",
    status_code=status.HTTP_201_CREATED,
    response_model=CreatedApiKeyResponse,
)
async def create_api_key(
    body: CreateApiKeyRequest,
    access: Annotated[OrgAccess, Depends(org_access(P.APIKEYS_MANAGE))],
    container: ContainerDep,
    client: ClientDep,
) -> CreatedApiKeyResponse:
    return await container.api_keys.create(access, body, client)


@router.get("/orgs/{org_id}/api-keys", response_model=list[ApiKeyResponse])
async def list_api_keys(
    access: Annotated[OrgAccess, Depends(org_access(P.APIKEYS_READ))], container: ContainerDep
) -> list[ApiKeyResponse]:
    return await container.api_keys.list_keys(access)


@router.delete("/orgs/{org_id}/api-keys/{api_key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    api_key_id: UUID,
    access: Annotated[OrgAccess, Depends(org_access(P.APIKEYS_MANAGE))],
    container: ContainerDep,
    client: ClientDep,
) -> Response:
    await container.api_keys.revoke(access, api_key_id, client)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------- audit log
@router.get("/orgs/{org_id}/audit-logs", response_model=Page[AuditLogEntry])
async def list_audit_logs(
    access: Annotated[OrgAccess, Depends(org_access(P.AUDIT_READ))],
    container: ContainerDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Annotated[str | None, Query(max_length=20, pattern=r"^\d+$")] = None,
    action: Annotated[str | None, Query(max_length=64, pattern=r"^[a-z0-9_.]+$")] = None,
) -> Page[AuditLogEntry]:
    before = int(cursor) if cursor else None
    if before is not None and before > 2**62:
        raise ValidationFailed("The pagination cursor is invalid.")
    rows = await container.audit.list_for_organization(
        access.scope, limit=limit + 1, before_id=before, action_prefix=action
    )
    next_cursor = str(rows[limit - 1].id) if len(rows) > limit else None
    return Page[AuditLogEntry](
        items=[AuditLogEntry.model_validate(row) for row in rows[:limit]], next_cursor=next_cursor
    )
