"""Projects and project-level membership."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import delete, or_, select
from sqlalchemy.exc import IntegrityError

from argus.core.clock import Clock
from argus.core.errors import Conflict, NotFound, PermissionDenied
from argus.core.pagination import Page, PageQuery, encode_cursor
from argus.infrastructure.db import Database
from argus.modules.audit.service import AuditCategory, AuditEvent, AuditService
from argus.modules.platform import quotas
from argus.modules.tenancy.authorization import OrgAccess, ProjectAccess
from argus.modules.tenancy.models import Project, ProjectMember
from argus.modules.tenancy.schemas import (
    CreateProjectRequest,
    ProjectMemberResponse,
    ProjectResponse,
    UpdateProjectRequest,
)
from argus.security.permissions import Permission, ProjectRole
from argus.security.principals import ClientInfo


class ProjectService:
    def __init__(self, *, database: Database, audit: AuditService, clock: Clock) -> None:
        self._db = database
        self._audit = audit
        self._clock = clock

    def _event(
        self, action: str, access: OrgAccess, client: ClientInfo, project_id: UUID, **kw: Any
    ) -> AuditEvent:
        return AuditEvent(
            action=action,
            category=kw.pop("category", AuditCategory.ORGANIZATION),
            actor=access.scope.actor,
            organization_id=access.organization_id,
            target_type="project",
            target_id=str(project_id),
            client=client,
            **kw,
        )

    async def create(
        self, access: OrgAccess, request: CreateProjectRequest, client: ClientInfo
    ) -> ProjectResponse:
        access.require(Permission.PROJECTS_CREATE)
        try:
            async with self._db.tenant(access.scope) as session:
                await quotas.enforce(
                    session, access.organization_id, "projects", now=self._clock.now()
                )
                project = Project(
                    organization_id=access.organization_id,
                    name=request.name,
                    description=request.description,
                    visibility=request.visibility,
                    created_by=access.principal.user_id,
                )
                session.add(project)
                await session.flush()
                if (
                    request.visibility == "restricted"
                    and not access.is_admin
                    and access.principal.user_id is not None
                ):
                    # the creator must not lock themselves out of their own project
                    session.add(
                        ProjectMember(
                            organization_id=access.organization_id,
                            project_id=project.id,
                            user_id=access.principal.user_id,
                            role=ProjectRole.EDITOR.value,
                            added_by=access.principal.user_id,
                        )
                    )
                await self._audit.record(
                    session,
                    self._event(
                        "project.created",
                        access,
                        client,
                        project.id,
                        details={"visibility": request.visibility},
                    ),
                )
                return ProjectResponse.model_validate(project)
        except IntegrityError as exc:
            if "uq_projects_organization_id_name" in str(exc.orig):
                raise Conflict("A project with this name already exists.") from None
            raise

    async def list_projects(self, access: OrgAccess, page: PageQuery) -> Page[ProjectResponse]:
        access.require(Permission.PROJECTS_READ)
        cursor = page.decoded()
        stmt = select(Project).where(Project.organization_id == access.organization_id)
        if not access.is_admin:
            member_projects = select(ProjectMember.project_id).where(
                ProjectMember.organization_id == access.organization_id,
                ProjectMember.user_id == access.principal.user_id,
            )
            stmt = stmt.where(
                or_(Project.visibility == "organization", Project.id.in_(member_projects))
            )
        if cursor is not None:
            stmt = stmt.where(
                (Project.created_at < cursor.created_at)
                | ((Project.created_at == cursor.created_at) & (Project.id < cursor.id))
            )
        stmt = stmt.order_by(Project.created_at.desc(), Project.id.desc()).limit(page.limit + 1)
        async with self._db.tenant(access.scope, read_only=True) as session:
            rows = list((await session.execute(stmt)).scalars().all())
        next_cursor = None
        if len(rows) > page.limit:
            rows = rows[: page.limit]
            next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id)
        return Page[ProjectResponse](
            items=[ProjectResponse.model_validate(row) for row in rows], next_cursor=next_cursor
        )

    async def update(
        self, access: ProjectAccess, request: UpdateProjectRequest, client: ClientInfo
    ) -> ProjectResponse:
        access.require(Permission.PROJECTS_UPDATE)
        if request.visibility is not None and not access.org.can(
            Permission.PROJECTS_MANAGE_MEMBERS
        ):
            raise PermissionDenied("Only administrators can change project visibility.")
        try:
            async with self._db.tenant(access.scope) as session:
                project = await session.get(Project, access.project_id, with_for_update=True)
                if project is None or project.organization_id != access.org.organization_id:
                    raise NotFound
                changed: list[str] = []
                if request.name is not None and request.name != project.name:
                    project.name = request.name
                    changed.append("name")
                if request.description is not None:
                    project.description = request.description
                    changed.append("description")
                if request.visibility is not None and request.visibility != project.visibility:
                    project.visibility = request.visibility
                    changed.append("visibility")
                if request.archived is not None:
                    project.archived_at = self._clock.now() if request.archived else None
                    changed.append("archived")
                await session.flush()
                await self._audit.record(
                    session,
                    self._event(
                        "project.updated",
                        access.org,
                        client,
                        project.id,
                        details={"changed": changed},
                    ),
                )
                return ProjectResponse.model_validate(project)
        except IntegrityError as exc:
            if "uq_projects_organization_id_name" in str(exc.orig):
                raise Conflict("A project with this name already exists.") from None
            raise

    async def delete(self, access: ProjectAccess, client: ClientInfo) -> None:
        access.org.require(Permission.PROJECTS_DELETE)
        async with self._db.tenant(access.scope) as session:
            await session.execute(
                delete(Project).where(
                    Project.organization_id == access.org.organization_id,
                    Project.id == access.project_id,
                )
            )
            await self._audit.record(
                session,
                self._event(
                    "project.deleted",
                    access.org,
                    client,
                    access.project_id,
                    category=AuditCategory.DATA_ACCESS,
                ),
            )

    # ------------------------------------------------------------- project members
    async def list_members(self, access: ProjectAccess) -> list[ProjectMemberResponse]:
        access.require(Permission.PROJECTS_READ)
        async with self._db.tenant(access.scope, read_only=True) as session:
            rows = (
                (
                    await session.execute(
                        select(ProjectMember).where(
                            ProjectMember.organization_id == access.org.organization_id,
                            ProjectMember.project_id == access.project_id,
                        )
                    )
                )
                .scalars()
                .all()
            )
        return [
            ProjectMemberResponse(
                user_id=r.user_id, role=ProjectRole(r.role), added_at=r.created_at
            )
            for r in rows
        ]

    async def set_member(
        self, access: ProjectAccess, user_id: UUID, role: ProjectRole, client: ClientInfo
    ) -> None:
        access.org.require(Permission.PROJECTS_MANAGE_MEMBERS)
        try:
            async with self._db.tenant(access.scope) as session:
                member = await session.get(ProjectMember, (access.project_id, user_id))
                if member is None:
                    session.add(
                        ProjectMember(
                            organization_id=access.org.organization_id,
                            project_id=access.project_id,
                            user_id=user_id,
                            role=role.value,
                            added_by=access.org.principal.user_id,
                        )
                    )
                else:
                    member.role = role.value
                await session.flush()
                await self._audit.record(
                    session,
                    self._event(
                        "project.member_set",
                        access.org,
                        client,
                        access.project_id,
                        category=AuditCategory.AUTHORIZATION,
                        details={"user_id": str(user_id), "role": role.value},
                    ),
                )
        except IntegrityError:
            # composite FK: the user is not a member of this organisation
            raise NotFound from None

    async def remove_member(self, access: ProjectAccess, user_id: UUID, client: ClientInfo) -> None:
        access.org.require(Permission.PROJECTS_MANAGE_MEMBERS)
        async with self._db.tenant(access.scope) as session:
            result = await session.execute(
                delete(ProjectMember).where(
                    ProjectMember.organization_id == access.org.organization_id,
                    ProjectMember.project_id == access.project_id,
                    ProjectMember.user_id == user_id,
                )
            )
            if result.rowcount == 0:  # type: ignore[attr-defined]
                raise NotFound
            await self._audit.record(
                session,
                self._event(
                    "project.member_removed",
                    access.org,
                    client,
                    access.project_id,
                    category=AuditCategory.AUTHORIZATION,
                    details={"user_id": str(user_id)},
                ),
            )
