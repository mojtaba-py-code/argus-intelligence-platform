"""Kill switches: stop an agent, a tool, a provider or a model immediately.

Checked before every agent iteration, every tool call and every model call. A switch applies to
one organisation or (``organization_id IS NULL``) to the whole platform; ``target = '*'`` covers
every agent/tool/provider/model, and ``kind = 'all'`` stops all AI activity. Lookups are cached
for a few seconds per process and organisation: a switch takes effect everywhere within that
window, without a database round trip on every call.

Engaging and releasing are audited with the real actor. Platform-wide switches can only be
written with the owner role (``argus killswitch``): row-level security lets the runtime role
write its own organisation's switches and merely *read* platform ones. Organisation
administrators manage their own switches through the security API (phase 19).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Literal
from uuid import UUID

from sqlalchemy import or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.clock import Clock
from argus.core.ids import uuid7
from argus.core.scope import Actor, TenantScope
from argus.infrastructure.db import Database
from argus.modules.agents.models import SWITCH_KINDS, KillSwitch
from argus.modules.audit.service import AuditCategory, AuditEvent, AuditService
from argus.security.principals import ClientInfo

SwitchKind = Literal["agent", "tool", "provider", "model"]
_TARGET: Final = re.compile(r"^(\*|[a-z0-9][a-z0-9_.:/-]{0,63})$")


class InvalidSwitch(ValueError):
    pass


class DuplicateSwitch(InvalidSwitch):
    """An identical switch (same scope, kind and target) is already active."""


@dataclass(frozen=True)
class SwitchView:
    id: UUID
    organization_id: UUID | None
    kind: str
    target: str
    active: bool
    reason: str
    created_by: str
    created_at: datetime
    expires_at: datetime | None


class KillSwitchService:
    def __init__(
        self,
        database: Database,
        clock: Clock,
        *,
        audit: AuditService | None = None,
        ttl_s: float = 5.0,
    ) -> None:
        self._db = database
        self._clock = clock
        self._audit = audit
        self._ttl = ttl_s
        self._cache: dict[UUID, tuple[float, frozenset[tuple[str, str]]]] = {}

    # ------------------------------------------------------------------------- checks
    async def _active(self, organization_id: UUID) -> frozenset[tuple[str, str]]:
        cached = self._cache.get(organization_id)
        if cached is not None and cached[0] > time.monotonic():
            return cached[1]
        async with self._db.tenant(
            TenantScope(organization_id, Actor.system()), read_only=True
        ) as session:
            rows = await session.execute(
                text(
                    "SELECT kind, target FROM kill_switches WHERE active"
                    " AND (expires_at IS NULL OR expires_at > :now)"
                    " AND (organization_id IS NULL OR organization_id = :org)"
                ),
                {"now": self._clock.now(), "org": organization_id},
            )
            active = frozenset((row.kind, row.target) for row in rows)
        self._cache[organization_id] = (time.monotonic() + self._ttl, active)
        return active

    async def blocked(self, organization_id: UUID, kind: SwitchKind, target: str) -> bool:
        active = await self._active(organization_id)
        return bool({("all", "*"), (kind, "*"), (kind, target)} & active)

    def forget(self, organization_id: UUID | None = None) -> None:
        if organization_id is None:
            self._cache.clear()
        else:
            self._cache.pop(organization_id, None)

    # --------------------------------------------------------------------- management
    async def engage(
        self,
        *,
        kind: str,
        target: str,
        reason: str,
        created_by: str,
        organization_id: UUID | None = None,
        expires_at: datetime | None = None,
        actor: Actor | None = None,
        client: ClientInfo | None = None,
    ) -> UUID:
        """Engage a switch. ``created_by`` is the label shown in listings; ``actor`` and
        ``client`` identify who did it in the audit log (the system, for operator commands)."""
        target = target.strip().lower()
        reason = " ".join(reason.split())
        if kind not in SWITCH_KINDS:
            msg = f"kind must be one of {', '.join(SWITCH_KINDS)}"
            raise InvalidSwitch(msg)
        if kind == "all" and target != "*":
            msg = "a switch of kind 'all' must target '*'"
            raise InvalidSwitch(msg)
        if not _TARGET.fullmatch(target):
            msg = "target must be '*' or a lowercase name (letters, digits, _ . : / -)"
            raise InvalidSwitch(msg)
        if not 3 <= len(reason) <= 500:
            msg = "give a reason of 3 to 500 characters"
            raise InvalidSwitch(msg)
        if expires_at is not None and expires_at <= self._clock.now():
            msg = "expiry must be in the future"
            raise InvalidSwitch(msg)
        switch_id = uuid7()
        async with self._db.session(organization_id=organization_id) as session:
            duplicate = (
                await session.execute(
                    select(KillSwitch.id).where(
                        KillSwitch.organization_id.is_(None)
                        if organization_id is None
                        else KillSwitch.organization_id == organization_id,
                        KillSwitch.kind == kind,
                        KillSwitch.target == target,
                        KillSwitch.active,
                        or_(
                            KillSwitch.expires_at.is_(None),
                            KillSwitch.expires_at > self._clock.now(),
                        ),
                    )
                )
            ).first()
            if duplicate is not None:
                msg = "an identical switch is already active"
                raise DuplicateSwitch(msg)
            session.add(
                KillSwitch(
                    id=switch_id,
                    organization_id=organization_id,
                    kind=kind,
                    target=target,
                    active=True,
                    reason=reason,
                    created_by=created_by[:200],
                    expires_at=expires_at,
                )
            )
            await session.flush()
            await self._record(
                session,
                "kill_switch.engaged",
                organization_id,
                switch_id,
                {"kind": kind, "target": target, "reason": reason, "by": created_by[:200]},
                actor=actor,
                client=client,
            )
        self.forget(organization_id)
        return switch_id

    async def release(
        self,
        switch_id: UUID,
        *,
        released_by: str,
        organization_id: UUID | None = None,
        actor: Actor | None = None,
        client: ClientInfo | None = None,
    ) -> bool:
        """Release an active switch. ``organization_id`` is the caller's organisation context:
        with one, only that organisation's switches match (row-level security enforces the same
        rule underneath, so the UPDATE matches no row otherwise). Without one - the operator CLI
        on the owner role - any switch matches. Success is decided by the rows changed."""
        conditions = [KillSwitch.id == switch_id, KillSwitch.active]
        if organization_id is not None:
            conditions.append(KillSwitch.organization_id == organization_id)
        async with self._db.session(organization_id=organization_id) as session:
            released = (
                await session.execute(
                    update(KillSwitch)
                    .where(*conditions)
                    .values(active=False, updated_at=self._clock.now())
                    .returning(KillSwitch.organization_id, KillSwitch.kind, KillSwitch.target)
                )
            ).one_or_none()
            if released is None:
                return False
            await self._record(
                session,
                "kill_switch.released",
                released.organization_id,
                switch_id,
                {"kind": released.kind, "target": released.target, "by": released_by[:200]},
                actor=actor,
                client=client,
            )
        self.forget(released.organization_id)
        return True

    async def list_switches(
        self,
        *,
        include_inactive: bool = False,
        organization_id: UUID | None = None,
        limit: int = 500,
    ) -> list[SwitchView]:
        """Newest first. With ``organization_id``: that organisation's switches and the
        platform-wide ones that also apply to it; without it, every switch the role can read."""
        now = self._clock.now()
        async with self._db.session(organization_id=organization_id, read_only=True) as session:
            stmt = select(KillSwitch).order_by(KillSwitch.created_at.desc()).limit(limit)
            if organization_id is not None:
                stmt = stmt.where(
                    or_(
                        KillSwitch.organization_id.is_(None),
                        KillSwitch.organization_id == organization_id,
                    )
                )
            if not include_inactive:
                stmt = stmt.where(
                    KillSwitch.active,
                    or_(KillSwitch.expires_at.is_(None), KillSwitch.expires_at > now),
                )
            rows = (await session.execute(stmt)).scalars().all()
        return [
            SwitchView(
                id=row.id,
                organization_id=row.organization_id,
                kind=row.kind,
                target=row.target,
                active=row.active and (row.expires_at is None or row.expires_at > now),
                reason=row.reason,
                created_by=row.created_by,
                created_at=row.created_at,
                expires_at=row.expires_at,
            )
            for row in rows
        ]

    async def _record(
        self,
        session: AsyncSession,
        action: str,
        organization_id: UUID | None,
        switch_id: UUID,
        details: dict[str, str],
        *,
        actor: Actor | None,
        client: ClientInfo | None,
    ) -> None:
        if self._audit is None:
            return
        await self._audit.record(
            session,
            AuditEvent(
                action=action,
                category=AuditCategory.SECURITY,
                actor=actor or Actor.system(),
                organization_id=organization_id,
                target_type="kill_switch",
                target_id=str(switch_id),
                client=client,
                details=details,
            ),
        )
