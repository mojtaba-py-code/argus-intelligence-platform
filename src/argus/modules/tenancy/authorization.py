"""The policy engine: from (principal, organisation, project) to an authorised scope.

Rules (deny by default):

* Not a member (or an API key bound to another organisation) → **404**, never 403: callers must
  not learn which organisations or projects exist.
* Member without the permission → 403.
* Effective permissions = role permissions ∩ API-key scopes (re-evaluated on every request, so a
  demotion immediately demotes the user's keys).
* Restricted projects: owners/admins keep access; others need a project role.
* Organisations that require MFA refuse interactive sessions that did not complete MFA.
* Platform administrators get **no** implicit access to tenant data (privacy by design); their
  powers live in separate, audited administrative commands.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.classification import Classification
from argus.core.errors import NotFound, PermissionDenied
from argus.core.scope import Actor, ActorType, TenantScope
from argus.infrastructure.db import Database
from argus.modules.tenancy.models import (
    Organization,
    OrganizationMember,
    Project,
    ProjectMember,
    ServiceAccount,
)
from argus.modules.tenancy.schemas import OrganizationSettings
from argus.security.permissions import (
    ORG_ROLE_PERMISSIONS,
    PROJECT_ROLE_PERMISSIONS,
    OrgRole,
    Permission,
    ProjectRole,
)
from argus.security.principals import Principal


@dataclass(frozen=True)
class OrgAccess:
    principal: Principal
    scope: TenantScope
    role: OrgRole
    permissions: frozenset[Permission]
    settings: OrganizationSettings

    @property
    def organization_id(self) -> UUID:
        return self.scope.organization_id

    @property
    def is_admin(self) -> bool:
        return self.role in (OrgRole.OWNER, OrgRole.ADMIN)

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions

    def require(self, permission: Permission) -> None:
        if permission not in self.permissions:
            raise PermissionDenied(log_context={"permission": permission.value})


@dataclass(frozen=True)
class ProjectAccess:
    org: OrgAccess
    project: Project
    scope: TenantScope
    permissions: frozenset[Permission]
    project_role: ProjectRole | None

    @property
    def project_id(self) -> UUID:
        return self.project.id

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions

    def require(self, permission: Permission) -> None:
        if permission not in self.permissions:
            raise PermissionDenied(log_context={"permission": permission.value})

    @property
    def classification_ceiling(self) -> Classification:
        """The most sensitive content this caller may read in the project."""
        return (
            Classification.RESTRICTED
            if self.can(Permission.DOCUMENTS_READ_RESTRICTED)
            else Classification.CONFIDENTIAL
        )


def actor_for(principal: Principal) -> Actor:
    if principal.api_key_id is not None:
        return Actor(ActorType.API_KEY, principal.api_key_id, principal.user_id)
    if principal.service_account_id is not None:
        return Actor(ActorType.SERVICE_ACCOUNT, principal.service_account_id, None)
    return Actor(ActorType.USER, principal.user_id, principal.user_id)


class Authorizer:
    def __init__(self, database: Database) -> None:
        self._db = database

    async def org(
        self, principal: Principal, organization_id: UUID, permission: Permission | None = None
    ) -> OrgAccess:
        if (
            principal.key_organization_id is not None
            and principal.key_organization_id != organization_id
        ):
            raise NotFound
        async with self._db.session(
            organization_id=organization_id, user_id=principal.user_id, read_only=True
        ) as session:
            access = await self._org_in(session, principal, organization_id)
        if permission is not None:
            access.require(permission)
        return access

    async def _org_in(
        self, session: AsyncSession, principal: Principal, organization_id: UUID
    ) -> OrgAccess:
        """The organisation rules, inside a session whose context is that organisation and
        the principal's user (what row-level security needs to show memberships)."""
        if (
            principal.key_organization_id is not None
            and principal.key_organization_id != organization_id
        ):
            raise NotFound
        org = (
            await session.execute(
                select(Organization.status, Organization.settings).where(
                    Organization.id == organization_id
                )
            )
        ).one_or_none()
        if org is None:
            raise NotFound
        role_value: str | None
        if principal.service_account_id is not None:
            row = (
                await session.execute(
                    select(ServiceAccount.role, ServiceAccount.disabled_at).where(
                        ServiceAccount.organization_id == organization_id,
                        ServiceAccount.id == principal.service_account_id,
                    )
                )
            ).one_or_none()
            role_value = row.role if row is not None and row.disabled_at is None else None
        elif principal.user_id is not None:
            role_value = (
                await session.execute(
                    select(OrganizationMember.role).where(
                        OrganizationMember.organization_id == organization_id,
                        OrganizationMember.user_id == principal.user_id,
                    )
                )
            ).scalar_one_or_none()
        else:
            role_value = None
        # Deleted (pending deletion, being purged) - or any status this code does not know:
        # the organisation does not exist for its members. Fails closed.
        if role_value is None or org.status not in {"active", "suspended"}:
            raise NotFound
        if org.status == "suspended":
            raise PermissionDenied("This organisation is suspended.")
        settings = OrganizationSettings.model_validate(org.settings or {})
        if settings.require_mfa and principal.is_interactive and not principal.mfa_verified:
            raise PermissionDenied(
                "This organisation requires two-step verification. Enable MFA and sign in again."
            )
        role = OrgRole(role_value)
        permissions = ORG_ROLE_PERMISSIONS[role]
        if principal.scopes is not None:
            permissions = permissions & principal.scopes
        return OrgAccess(
            principal=principal,
            scope=TenantScope(organization_id, actor_for(principal)),
            role=role,
            permissions=permissions,
            settings=settings,
        )

    async def project(
        self,
        principal: Principal,
        organization_id: UUID,
        project_id: UUID,
        permission: Permission | None = None,
    ) -> ProjectAccess:
        # One transaction for both checks: the organisation context and the principal's user
        # are exactly the tenant scope the project lookup needs.
        async with self._db.session(
            organization_id=organization_id, user_id=principal.user_id, read_only=True
        ) as session:
            org_access = await self._org_in(session, principal, organization_id)
            project = (
                await session.execute(
                    select(Project).where(
                        Project.organization_id == organization_id, Project.id == project_id
                    )
                )
            ).scalar_one_or_none()
            if project is None:
                raise NotFound
            project_role: ProjectRole | None = None
            if project.visibility == "restricted" and not org_access.is_admin:
                member_role = None
                if principal.user_id is not None and principal.service_account_id is None:
                    member_role = (
                        await session.execute(
                            select(ProjectMember.role).where(
                                ProjectMember.project_id == project_id,
                                ProjectMember.user_id == principal.user_id,
                            )
                        )
                    ).scalar_one_or_none()
                if member_role is None:
                    raise NotFound  # existence of restricted projects is not disclosed
                project_role = ProjectRole(member_role)
                permissions = PROJECT_ROLE_PERMISSIONS[project_role]
                if principal.scopes is not None:
                    permissions = permissions & principal.scopes
            else:
                permissions = org_access.permissions
        access = ProjectAccess(
            org=org_access,
            project=project,
            scope=org_access.scope.with_project(project_id),
            permissions=permissions,
            project_role=project_role,
        )
        if permission is not None:
            access.require(permission)
        return access
