"""The security centre: what an organisation's administrators use to watch and stop things.

Permissions: reading (summary, events, switches, verifications) needs ``audit:read``; changing
anything (kill switches, a manual verification) needs ``security:manage``, which API keys can
never carry - stopping or resuming AI activity is a decision for a signed-in administrator.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Final
from uuid import UUID

from sqlalchemy import select

from argus.core.clock import Clock
from argus.core.errors import Conflict, NotFound, RateLimited, ValidationFailed
from argus.core.events import Event, EventSink
from argus.core.logging import get_logger
from argus.infrastructure.db import Database
from argus.infrastructure.observability.metrics import Metrics
from argus.modules.agents.killswitch import (
    DuplicateSwitch,
    InvalidSwitch,
    KillSwitchService,
    SwitchView,
)
from argus.modules.audit.models import AuditLog
from argus.modules.audit.service import AuditCategory, AuditEvent, AuditOutcome, AuditService
from argus.modules.security_center import posture
from argus.modules.security_center.integrity import SECURITY_LINK, AuditIntegrity
from argus.modules.security_center.models import AuditVerification
from argus.modules.security_center.schemas import (
    AuditVerificationResponse,
    EngageKillSwitchRequest,
    KillSwitchResponse,
    SecuritySummary,
)
from argus.modules.tenancy.authorization import OrgAccess
from argus.modules.tenancy.models import OrganizationMember
from argus.security.principals import ClientInfo
from argus.security.ratelimit import POLICIES, RateLimiter
from argus.security.text import clean_line

log = get_logger(__name__)
ADMIN_ROLES: Final = ("owner", "admin")


@dataclass(frozen=True)
class SecurityDependencies:
    database: Database
    audit: AuditService
    kill_switches: KillSwitchService
    integrity: AuditIntegrity
    events: EventSink
    limiter: RateLimiter
    clock: Clock
    metrics: Metrics
    known_targets: Mapping[str, frozenset[str]]
    """Names a switch of each kind may target besides ``*``; a kind missing here (models) takes
    any well-formed name. A typo must not leave an administrator believing something stopped."""


class SecurityCenterService:
    def __init__(self, deps: SecurityDependencies) -> None:
        self._d = deps

    # ----------------------------------------------------------------------- kill switches
    async def list_switches(
        self, access: OrgAccess, *, include_inactive: bool = False
    ) -> list[KillSwitchResponse]:
        views = await self._d.kill_switches.list_switches(
            organization_id=access.organization_id, include_inactive=include_inactive
        )
        return [self._switch(view) for view in views]

    async def engage(
        self, access: OrgAccess, body: EngageKillSwitchRequest, client: ClientInfo
    ) -> KillSwitchResponse:
        d = self._d
        target = body.target
        if body.kind == "all" and target != "*":
            raise ValidationFailed("A switch of kind 'all' must target '*'.")
        known = d.known_targets.get(body.kind)
        if target != "*" and known is not None and target not in known:
            names = ", ".join(sorted(known))
            raise ValidationFailed(f"Unknown {body.kind} '{target}'. Use '*' or one of: {names}.")
        expires_at = (
            d.clock.now() + timedelta(minutes=body.expires_in_minutes)
            if body.expires_in_minutes is not None
            else None
        )
        label = self._label(access)
        try:
            switch_id = await d.kill_switches.engage(
                kind=body.kind,
                target=target,
                reason=body.reason,
                created_by=label,
                organization_id=access.organization_id,
                expires_at=expires_at,
                actor=access.scope.actor,
                client=client,
            )
        except DuplicateSwitch as exc:
            raise Conflict("An identical kill switch is already active.") from exc
        except InvalidSwitch as exc:
            raise ValidationFailed(str(exc).capitalize() + ".") from exc
        await d.events.emit(
            Event(
                type="security.kill_switch.engaged",
                organization_id=access.organization_id,
                title=f"Kill switch engaged: {body.kind} {target}",
                body=(
                    f"An administrator ({label}) stopped {self._describe(body.kind, target)}"
                    f" for this organisation. Reason: {clean_line(body.reason, 300) or '-'}"
                ),
                link=SECURITY_LINK,
                recipients=await self._administrators(access.organization_id),
                email=True,
                data={"switch_id": str(switch_id), "kind": body.kind, "target": target},
            )
        )
        views = await d.kill_switches.list_switches(organization_id=access.organization_id)
        for view in views:
            if view.id == switch_id:
                return self._switch(view)
        raise NotFound  # pragma: no cover - released between the two statements

    async def release(self, access: OrgAccess, switch_id: UUID, client: ClientInfo) -> None:
        released = await self._d.kill_switches.release(
            switch_id,
            released_by=self._label(access),
            organization_id=access.organization_id,
            actor=access.scope.actor,
            client=client,
        )
        if not released:
            raise NotFound  # unknown, inactive, platform-wide or another organisation's

    # ------------------------------------------------------------------------- posture
    async def summary(self, access: OrgAccess, *, days: int) -> SecuritySummary:
        d = self._d
        org = access.organization_id
        now = d.clock.now()
        since = now - timedelta(days=days)
        async with d.database.tenant(access.scope, read_only=True) as session:
            access_signals = await posture.access_signals(session, org, since)
            agents = await posture.agent_signals(session, org, since)
            content = await posture.content_signals(session, org, since)
            egress = await posture.egress_signals(session, org, since)
            models = await posture.model_signals(session, org, since)
            credentials = await posture.credential_signals(session, org, now)
            members = await posture.member_signals(
                session, org, require_mfa=access.settings.require_mfa
            )
            latest = (
                await session.execute(
                    select(AuditVerification)
                    .where(AuditVerification.organization_id == org)
                    .order_by(AuditVerification.verified_at.desc(), AuditVerification.id.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
        switches = await self.list_switches(access)
        verification = AuditVerificationResponse.model_validate(latest) if latest else None
        return SecuritySummary(
            window_days=days,
            generated_at=now,
            access=access_signals,
            agents=agents,
            content=content,
            egress=egress,
            models=models,
            credentials=credentials,
            members=members,
            kill_switches=switches,
            last_audit_verification=verification,
            recommendations=posture.recommendations(
                now=now,
                access=access_signals,
                agents=agents,
                content=content,
                credentials=credentials,
                members=members,
                switches=switches,
                verification=verification,
            ),
        )

    async def events(
        self, access: OrgAccess, *, limit: int, before_id: int | None
    ) -> list[AuditLog]:
        return await self._d.audit.list_for_organization(
            access.scope, limit=limit, before_id=before_id, security_only=True
        )

    # ----------------------------------------------------------------- audit integrity
    async def verifications(
        self, access: OrgAccess, *, limit: int
    ) -> list[AuditVerificationResponse]:
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            rows = (
                await session.execute(
                    select(AuditVerification)
                    .where(AuditVerification.organization_id == access.organization_id)
                    .order_by(AuditVerification.verified_at.desc(), AuditVerification.id.desc())
                    .limit(limit)
                )
            ).scalars()
            return [AuditVerificationResponse.model_validate(row) for row in rows]

    async def verify_now(self, access: OrgAccess) -> AuditVerificationResponse:
        decision = await self._d.limiter.hit(
            POLICIES["security.audit_verify.org"], str(access.organization_id)
        )
        if not decision.allowed:
            raise RateLimited(decision.retry_after_s)
        return await self._d.integrity.verify(
            access.organization_id, trigger="manual", requested_by=access.principal.user_id
        )

    # ------------------------------------------------------------------- denied access
    async def record_denial(
        self,
        access: OrgAccess,
        *,
        method: str,
        route: str,
        permission: str | None,
        detail: str,
        client: ClientInfo,
    ) -> None:
        """Write a member's refused action to the audit log, within a per-principal budget.

        Only members reach this point (non-members get 404 before any organisation context
        exists), so nobody can write into an organisation's audit log from outside it, and the
        budget stops one member from flooding it. Over-budget denials are still counted.
        """
        actor = access.scope.actor
        key = f"{access.organization_id}:{actor.type.value}:{actor.id}"
        decision = await self._d.limiter.hit(POLICIES["audit.denials.principal"], key)
        self._d.metrics.access_denied.labels(str(decision.allowed).lower()).inc()
        if not decision.allowed:
            return
        details: dict[str, str] = {
            "method": method[:8],
            "route": route[:200],
            "detail": clean_line(detail, 200) or "-",
        }
        if permission:
            details["permission"] = permission[:48]
        await self._d.audit.record_detached(
            AuditEvent(
                action="access.denied",
                category=AuditCategory.AUTHORIZATION,
                actor=actor,
                outcome=AuditOutcome.DENIED,
                organization_id=access.organization_id,
                target_type="route",
                target_id=route[:64],
                client=client,
                details=details,
            )
        )

    # ------------------------------------------------------------------------- helpers
    async def _administrators(self, organization_id: UUID) -> tuple[UUID, ...]:
        async with self._d.database.session(organization_id=organization_id, read_only=True) as s:
            rows = await s.execute(
                select(OrganizationMember.user_id)
                .where(
                    OrganizationMember.organization_id == organization_id,
                    OrganizationMember.role.in_(ADMIN_ROLES),
                )
                .order_by(OrganizationMember.user_id)
            )
            return tuple(rows.scalars().all())

    @staticmethod
    def _label(access: OrgAccess) -> str:
        actor = access.scope.actor
        return f"{actor.type.value}:{actor.id}"

    @staticmethod
    def _describe(kind: str, target: str) -> str:
        if kind == "all":
            return "all AI activity"
        return f"every {kind}" if target == "*" else f"the {kind} '{target}'"

    @staticmethod
    def _switch(view: SwitchView) -> KillSwitchResponse:
        platform = view.organization_id is None
        return KillSwitchResponse(
            id=view.id,
            scope="platform" if platform else "organization",
            kind=view.kind,
            target=view.target,
            active=view.active,
            reason=view.reason,
            created_by="platform operator" if platform else view.created_by,
            created_at=view.created_at,
            expires_at=view.expires_at,
            editable=not platform and view.active,
        )
