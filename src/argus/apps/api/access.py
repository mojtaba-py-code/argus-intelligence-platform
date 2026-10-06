"""Authorisation dependencies: resolve ``{org_id}`` / ``{project_id}`` path parameters into an
authorised :class:`OrgAccess` / :class:`ProjectAccess` (or 404/403) before the handler runs.

Once membership is established the organisation access is also kept on ``request.state``, so
that a permission denial raised anywhere later in the request (the route's permission, a role
rule inside a service) can be written to that organisation's audit log by the error handler.
It is used for that record only - never to authorise anything.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from uuid import UUID

from fastapi import Request

from argus.apps.api.middleware import route_template
from argus.apps.api.security import ContainerDep, PrincipalDep, client_info
from argus.core import context
from argus.core.errors import PermissionDenied
from argus.modules.tenancy.authorization import OrgAccess, ProjectAccess
from argus.security.permissions import Permission

DENIAL_STATE = "argus_org_access"


def org_access(
    permission: Permission | None = None,
) -> Callable[..., Awaitable[OrgAccess]]:
    async def dependency(
        request: Request, org_id: UUID, principal: PrincipalDep, container: ContainerDep
    ) -> OrgAccess:
        access = await container.authorizer.org(principal, org_id)
        context.set_value("organization_id", org_id)
        setattr(request.state, DENIAL_STATE, access)
        if permission is not None:
            access.require(permission)
        return access

    return dependency


def project_access(
    permission: Permission | None = None,
) -> Callable[..., Awaitable[ProjectAccess]]:
    async def dependency(
        request: Request,
        org_id: UUID,
        project_id: UUID,
        principal: PrincipalDep,
        container: ContainerDep,
    ) -> ProjectAccess:
        access = await container.authorizer.project(principal, org_id, project_id)
        context.set_value("organization_id", org_id)
        context.set_value("project_id", project_id)
        setattr(request.state, DENIAL_STATE, access.org)
        if permission is not None:
            access.require(permission)
        return access

    return dependency


async def audit_permission_denied(request: Request, exc: PermissionDenied) -> None:
    """Error-handler hook: record a member's denied action (best effort, rate-limited)."""
    access = getattr(request.state, DENIAL_STATE, None)
    container = getattr(request.app.state, "container", None)
    if not isinstance(access, OrgAccess) or container is None:
        return
    permission = exc.log_context.get("permission")
    await container.security.record_denial(
        access,
        method=request.method,
        route=route_template(request.scope) or "unknown",
        permission=str(permission) if permission else None,
        detail=exc.detail,
        client=client_info(request),
    )
