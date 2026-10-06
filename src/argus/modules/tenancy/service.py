"""Organisations, memberships and invitations."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import Row, delete, func, select, text, update
from sqlalchemy.exc import IntegrityError

from argus.core.clock import Clock
from argus.core.config import AuthSettings, EmailSettings
from argus.core.crypto import sha256
from argus.core.errors import Conflict, NotFound, PermissionDenied, RateLimited, ValidationFailed
from argus.core.ids import secret_token, uuid7
from argus.core.logging import get_logger
from argus.core.scope import TenantScope
from argus.infrastructure.db import Database
from argus.infrastructure.email import EmailMessage, Mailer
from argus.modules.audit.service import AuditCategory, AuditEvent, AuditService
from argus.modules.identity.models import User
from argus.modules.platform import quotas
from argus.modules.tenancy.authorization import OrgAccess, actor_for
from argus.modules.tenancy.models import ApiKey, Invitation, Organization, OrganizationMember
from argus.modules.tenancy.schemas import (
    CreateInvitationRequest,
    CreateOrganizationRequest,
    InvitationResponse,
    MemberResponse,
    OrganizationResponse,
    OrganizationSettings,
    UpdateOrganizationRequest,
)
from argus.security.permissions import ROLE_RANK, OrgRole
from argus.security.principals import ClientInfo, Principal
from argus.security.ratelimit import POLICIES, RateLimiter

log = get_logger(__name__)
_SLUG_CLEAN = re.compile(r"[^a-z0-9]+")


def _slug_from_name(name: str) -> str:
    base = _SLUG_CLEAN.sub("-", name.lower()).strip("-")[:40] or "org"
    if len(base) < 3:
        base = f"{base}-org"
    return f"{base}-{secrets.token_hex(3)}"


@dataclass(frozen=True)
class TenancyDependencies:
    database: Database
    audit: AuditService
    mailer: Mailer
    limiter: RateLimiter
    clock: Clock
    auth: AuthSettings
    email: EmailSettings
    default_plan: str = "enterprise"


class OrganizationService:
    def __init__(self, deps: TenancyDependencies) -> None:
        self._d = deps

    def _event(self, action: str, scope: TenantScope, client: ClientInfo, **kw: Any) -> AuditEvent:
        return AuditEvent(
            action=action,
            category=kw.pop("category", AuditCategory.ORGANIZATION),
            actor=scope.actor,
            organization_id=scope.organization_id,
            client=client,
            **kw,
        )

    # ---------------------------------------------------------------- organisations
    async def create(
        self, principal: Principal, request: CreateOrganizationRequest, client: ClientInfo
    ) -> OrganizationResponse:
        if principal.user_id is None or principal.session_id is None:
            raise PermissionDenied("Organisations are created by signed-in users.")
        org_id = uuid7()
        slug = request.slug or _slug_from_name(request.name)
        scope = TenantScope(org_id, actor_for(principal))
        try:
            async with self._d.database.session(
                organization_id=org_id, user_id=principal.user_id
            ) as session:
                organization = Organization(
                    id=org_id,
                    name=request.name,
                    slug=slug,
                    plan=self._d.default_plan,
                    settings=OrganizationSettings().model_dump(mode="json"),
                )
                session.add(organization)
                await session.flush()
                session.add(
                    OrganizationMember(
                        organization_id=org_id, user_id=principal.user_id, role=OrgRole.OWNER.value
                    )
                )
                await session.flush()
                await self._d.audit.record(
                    session,
                    self._event(
                        "org.created",
                        scope,
                        client,
                        target_type="organization",
                        target_id=str(org_id),
                        details={"slug": slug},
                    ),
                )
                return OrganizationResponse.model_validate(organization).model_copy(
                    update={"role": OrgRole.OWNER}
                )
        except IntegrityError as exc:
            if "uq_organizations_slug" in str(exc.orig):
                raise Conflict("This organisation slug is already taken.") from None
            raise

    async def list_mine(self, principal: Principal) -> list[OrganizationResponse]:
        if principal.key_organization_id is not None:
            # an API key sees exactly its own organisation
            ids: list[UUID] = [principal.key_organization_id]
        elif principal.user_id is None:
            return []
        else:
            ids = []
        async with self._d.database.session(user_id=principal.user_id, read_only=True) as session:
            stmt = (
                select(Organization, OrganizationMember.role)
                .join(OrganizationMember, OrganizationMember.organization_id == Organization.id)
                .where(
                    OrganizationMember.user_id == principal.user_id,
                    Organization.status.in_(("active", "suspended")),
                )
                .order_by(Organization.name)
                .limit(500)
            )
            if ids:
                stmt = stmt.where(Organization.id.in_(ids))
            rows = (await session.execute(stmt)).all()
        return [
            OrganizationResponse.model_validate(org).model_copy(update={"role": OrgRole(role)})
            for org, role in rows
        ]

    async def get(self, access: OrgAccess) -> OrganizationResponse:
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            org = await session.get(Organization, access.organization_id)
            if org is None:
                raise NotFound
            response = OrganizationResponse.model_validate(org).model_copy(
                update={"role": access.role}
            )
            if access.is_admin:
                response = response.model_copy(update={"settings": access.settings})
            return response

    async def update(
        self, access: OrgAccess, request: UpdateOrganizationRequest, client: ClientInfo
    ) -> OrganizationResponse:
        async with self._d.database.tenant(access.scope) as session:
            org = await session.get(Organization, access.organization_id, with_for_update=True)
            if org is None:
                raise NotFound
            settings = OrganizationSettings.model_validate(org.settings or {})
            ceiling = quotas.plan_for(org.plan).monthly_llm_usd
            if (
                request.budgets is not None
                and ceiling is not None
                and request.budgets.monthly_llm_usd > ceiling
            ):
                raise ValidationFailed(
                    f"The {org.plan} plan allows a monthly model budget of at most ${ceiling:,.0f}."
                )
            changes: dict[str, Any] = {}
            if request.name is not None:
                org.name = request.name
                changes["name"] = request.name
            updated = settings.model_copy(
                update={
                    key: value
                    for key, value in {
                        "require_mfa": request.require_mfa,
                        "data_policy": request.data_policy,
                        "budgets": request.budgets,
                        "retention": request.retention,
                    }.items()
                    if value is not None
                }
            )
            if updated != settings:
                org.settings = updated.model_dump(mode="json")
                changes["settings"] = sorted(
                    k
                    for k in ("require_mfa", "data_policy", "budgets", "retention")
                    if getattr(updated, k) != getattr(settings, k)
                )
            await self._d.audit.record(
                session,
                self._event(
                    "org.updated",
                    access.scope,
                    client,
                    category=AuditCategory.CONFIGURATION,
                    target_type="organization",
                    target_id=str(org.id),
                    details=changes,
                ),
            )
            return OrganizationResponse.model_validate(org).model_copy(
                update={"role": access.role, "settings": updated}
            )

    async def request_deletion(self, access: OrgAccess, client: ClientInfo) -> None:
        async with self._d.database.tenant(access.scope) as session:
            org = await session.get(Organization, access.organization_id, with_for_update=True)
            if org is None:
                raise NotFound
            org.status = "pending_deletion"
            org.deletion_requested_at = self._d.clock.now()
            await session.execute(
                update(ApiKey)
                .where(ApiKey.organization_id == org.id, ApiKey.revoked_at.is_(None))
                .values(revoked_at=self._d.clock.now())
            )
            await self._d.audit.record(
                session,
                self._event(
                    "org.deletion_requested",
                    access.scope,
                    client,
                    category=AuditCategory.ADMINISTRATION,
                    target_type="organization",
                    target_id=str(org.id),
                ),
            )

    # --------------------------------------------------------------------- members
    async def list_members(self, access: OrgAccess) -> list[MemberResponse]:
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            rows = (
                await session.execute(
                    select(OrganizationMember, User.email, User.full_name)
                    .join(User, User.id == OrganizationMember.user_id)
                    .where(OrganizationMember.organization_id == access.organization_id)
                    .order_by(OrganizationMember.created_at)
                    .limit(2000)
                )
            ).all()
        return [
            MemberResponse(
                user_id=member.user_id,
                email=email,
                full_name=full_name,
                role=OrgRole(member.role),
                joined_at=member.created_at,
            )
            for member, email, full_name in rows
        ]

    async def _owners(self, session: Any, organization_id: UUID) -> int:
        result = await session.execute(
            select(func.count())
            .select_from(OrganizationMember)
            .where(
                OrganizationMember.organization_id == organization_id,
                OrganizationMember.role == OrgRole.OWNER.value,
            )
        )
        return int(result.scalar_one())

    async def change_role(
        self, access: OrgAccess, user_id: UUID, role: OrgRole, client: ClientInfo
    ) -> None:
        if user_id == access.principal.user_id:
            raise PermissionDenied("You cannot change your own role.")
        async with self._d.database.tenant(access.scope) as session:
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
                {"k": f"members:{access.organization_id}"},
            )
            member = (
                await session.execute(
                    select(OrganizationMember)
                    .where(
                        OrganizationMember.organization_id == access.organization_id,
                        OrganizationMember.user_id == user_id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if member is None:
                raise NotFound
            current = OrgRole(member.role)
            if OrgRole.OWNER in (current, role) and access.role is not OrgRole.OWNER:
                raise PermissionDenied("Only owners can grant or remove the owner role.")
            if (
                current is OrgRole.OWNER
                and role is not OrgRole.OWNER
                and await self._owners(session, access.organization_id) <= 1
            ):
                raise Conflict("An organisation needs at least one owner.")
            member.role = role.value
            await self._d.audit.record(
                session,
                self._event(
                    "member.role_changed",
                    access.scope,
                    client,
                    category=AuditCategory.AUTHORIZATION,
                    target_type="user",
                    target_id=str(user_id),
                    details={"from": current.value, "to": role.value},
                ),
            )

    async def remove_member(self, access: OrgAccess, user_id: UUID, client: ClientInfo) -> None:
        leaving = user_id == access.principal.user_id
        async with self._d.database.tenant(access.scope) as session:
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
                {"k": f"members:{access.organization_id}"},
            )
            member = (
                await session.execute(
                    select(OrganizationMember)
                    .where(
                        OrganizationMember.organization_id == access.organization_id,
                        OrganizationMember.user_id == user_id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if member is None:
                raise NotFound
            if member.role == OrgRole.OWNER.value:
                if not leaving and access.role is not OrgRole.OWNER:
                    raise PermissionDenied("Only owners can remove an owner.")
                if await self._owners(session, access.organization_id) <= 1:
                    raise Conflict("The last owner cannot leave. Transfer ownership first.")
            await session.execute(
                delete(OrganizationMember).where(
                    OrganizationMember.organization_id == access.organization_id,
                    OrganizationMember.user_id == user_id,
                )
            )
            await session.execute(
                update(ApiKey)
                .where(
                    ApiKey.organization_id == access.organization_id,
                    ApiKey.owner_user_id == user_id,
                    ApiKey.revoked_at.is_(None),
                )
                .values(revoked_at=self._d.clock.now())
            )
            await self._d.audit.record(
                session,
                self._event(
                    "member.left" if leaving else "member.removed",
                    access.scope,
                    client,
                    category=AuditCategory.AUTHORIZATION,
                    target_type="user",
                    target_id=str(user_id),
                ),
            )

    # ----------------------------------------------------------------- invitations
    async def invite(
        self, access: OrgAccess, request: CreateInvitationRequest, client: ClientInfo
    ) -> InvitationResponse:
        if ROLE_RANK[request.role] > ROLE_RANK[access.role]:
            raise PermissionDenied("You cannot invite someone with a higher role than your own.")
        decision = await self._d.limiter.hit(
            POLICIES["invitations.create.org"], str(access.organization_id)
        )
        if not decision.allowed:
            raise RateLimited(decision.retry_after_s)
        token = secret_token("argus_iv")
        now = self._d.clock.now()
        async with self._d.database.tenant(access.scope) as session:
            already = (
                await session.execute(
                    select(OrganizationMember.user_id)
                    .join(User, User.id == OrganizationMember.user_id)
                    .where(
                        OrganizationMember.organization_id == access.organization_id,
                        User.email == request.email,
                    )
                )
            ).scalar_one_or_none()
            if already is not None:
                raise Conflict("This person is already a member.")
            # A new invitation replaces this person's open one, so it is revoked before the
            # seats are counted: re-sending an invitation never needs a free seat.
            await session.execute(
                update(Invitation)
                .where(
                    Invitation.organization_id == access.organization_id,
                    Invitation.email == request.email,
                    Invitation.accepted_at.is_(None),
                    Invitation.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
            await quotas.enforce(session, access.organization_id, "members", now=now)
            invitation = Invitation(
                organization_id=access.organization_id,
                email=request.email,
                role=request.role.value,
                token_hash=sha256(token),
                invited_by=access.principal.user_id or uuid7(),
                expires_at=now + timedelta(seconds=self._d.auth.invitation_ttl_s),
            )
            session.add(invitation)
            await session.flush()
            org_name = (
                await session.execute(
                    select(Organization.name).where(Organization.id == access.organization_id)
                )
            ).scalar_one()
            await self._d.audit.record(
                session,
                self._event(
                    "invitation.created",
                    access.scope,
                    client,
                    target_type="invitation",
                    target_id=str(invitation.id),
                    details={"role": request.role.value},
                ),
            )
            response = InvitationResponse.model_validate(invitation)
        await self._send(
            EmailMessage(
                to=request.email,
                subject="You have been invited to an Argus organisation",
                text=(
                    f'You have been invited to join the organisation "{org_name[:80]}" on Argus '
                    f"as {request.role.value}.\n\nAccept the invitation (sign in or create an "
                    f"account with this e-mail address first):\n"
                    f"{str(self._d.email.app_base_url).rstrip('/')}/accept-invitation#token={token}"
                    f"\n\nThe invitation expires in {self._d.auth.invitation_ttl_s // 86400} days."
                ),
            )
        )
        return response

    async def _send(self, message: EmailMessage) -> None:
        try:
            await self._d.mailer.send(message)
        except Exception as exc:  # noqa: BLE001 - delivery is best effort after commit
            log.error(
                "email.delivery_failed", category=message.category, error_type=type(exc).__name__
            )

    async def list_invitations(self, access: OrgAccess) -> list[InvitationResponse]:
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            rows = (
                (
                    await session.execute(
                        select(Invitation)
                        .where(Invitation.organization_id == access.organization_id)
                        .order_by(Invitation.created_at.desc())
                        .limit(500)
                    )
                )
                .scalars()
                .all()
            )
        return [InvitationResponse.model_validate(row) for row in rows]

    async def revoke_invitation(
        self, access: OrgAccess, invitation_id: UUID, client: ClientInfo
    ) -> None:
        async with self._d.database.tenant(access.scope) as session:
            result = await session.execute(
                update(Invitation)
                .where(
                    Invitation.organization_id == access.organization_id,
                    Invitation.id == invitation_id,
                    Invitation.accepted_at.is_(None),
                    Invitation.revoked_at.is_(None),
                )
                .values(revoked_at=self._d.clock.now())
            )
            if result.rowcount == 0:  # type: ignore[attr-defined]
                raise NotFound
            await self._d.audit.record(
                session,
                self._event(
                    "invitation.revoked",
                    access.scope,
                    client,
                    target_type="invitation",
                    target_id=str(invitation_id),
                ),
            )

    async def accept_invitation(
        self, principal: Principal, token: str, client: ClientInfo
    ) -> OrganizationResponse:
        if principal.user_id is None or principal.session_id is None:
            raise PermissionDenied("Invitations are accepted by signed-in users.")
        invalid = ValidationFailed("The invitation is invalid or has expired.")
        async with self._d.database.session(user_id=principal.user_id, read_only=True) as session:
            row: Row[Any] | None = (
                await session.execute(
                    text("SELECT * FROM argus_find_invitation(:h)"), {"h": sha256(token)}
                )
            ).one_or_none()
            user = await session.get(User, principal.user_id)
        now = self._d.clock.now()
        if (
            row is None
            or user is None
            or row.accepted_at is not None
            or row.revoked_at is not None
            or row.expires_at <= now
        ):
            raise invalid
        if user.email_verified_at is None or user.email != row.email:
            raise PermissionDenied("This invitation was sent to a different e-mail address.")
        scope = TenantScope(row.organization_id, actor_for(principal))
        async with self._d.database.tenant(scope) as session:
            invitation = (
                await session.execute(
                    select(Invitation).where(Invitation.id == row.id).with_for_update()
                )
            ).scalar_one()
            if invitation.accepted_at is not None or invitation.revoked_at is not None:
                raise invalid
            invitation.accepted_at = now
            invitation.accepted_by = principal.user_id
            existing = await session.get(
                OrganizationMember, (row.organization_id, principal.user_id)
            )
            if existing is None:
                session.add(
                    OrganizationMember(
                        organization_id=row.organization_id,
                        user_id=principal.user_id,
                        role=invitation.role,
                        invited_by=invitation.invited_by,
                    )
                )
            org = await session.get(Organization, row.organization_id)
            await self._d.audit.record(
                session,
                self._event(
                    "member.joined",
                    scope,
                    client,
                    category=AuditCategory.AUTHORIZATION,
                    target_type="user",
                    target_id=str(principal.user_id),
                    details={"role": invitation.role, "via": "invitation"},
                ),
            )
            if org is None:
                raise NotFound
            return OrganizationResponse.model_validate(org).model_copy(
                update={"role": OrgRole(existing.role if existing else invitation.role)}
            )
