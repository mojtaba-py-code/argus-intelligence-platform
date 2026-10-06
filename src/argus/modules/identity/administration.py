"""Operator containment for a compromised account (incident response, spec §65).

``disable`` is one step that cuts every way the account acts:

* the account status becomes ``disabled`` - sign-in is refused, every request with an existing
  access token fails the per-request session check, and API keys owned by the account fail
  authentication (their owner must be active);
* every open session is revoked in the database and in the shared session cache, so nothing
  waits for a cache entry to expire and re-enabling the account never revives an old session.

``enable`` only restores the status: the person signs in again, and organisation administrators
decide separately whether the account's API keys should be rotated. Both are audited in the
platform chain with the operator's reason.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from sqlalchemy import update

from argus.core.clock import Clock
from argus.core.scope import Actor
from argus.infrastructure.db import Database
from argus.modules.audit.service import AuditCategory, AuditEvent, AuditService
from argus.modules.identity.models import User, UserSession
from argus.modules.identity.session_cache import SessionCache


@dataclass(frozen=True)
class StatusChange:
    user_id: UUID
    sessions_revoked: int


async def set_account_status(
    *,
    database: Database,
    audit: AuditService,
    sessions: SessionCache,
    clock: Clock,
    email: str,
    status: Literal["active", "disabled"],
    reason: str,
) -> StatusChange | None:
    """``None`` when no account has that e-mail address."""
    reason = " ".join(reason.split())[:300]
    if len(reason) < 3:
        msg = "give a reason of at least 3 characters (it is kept in the audit log)"
        raise ValueError(msg)
    now = clock.now()
    async with database.session() as session:
        user_id = (
            await session.execute(
                update(User)
                .where(User.email == email.strip().lower())
                .values(status=status, updated_at=now)
                .returning(User.id)
            )
        ).scalar_one_or_none()
        if user_id is None:
            return None
        revoked: list[UUID] = []
        if status == "disabled":
            revoked = list(
                (
                    await session.execute(
                        update(UserSession)
                        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
                        .values(revoked_at=now, revoked_reason="account_disabled")
                        .returning(UserSession.id)
                    )
                ).scalars()
            )
        await audit.record(
            session,
            AuditEvent(
                action="user.disabled" if status == "disabled" else "user.enabled",
                category=AuditCategory.ADMINISTRATION,
                actor=Actor.system(),
                target_type="user",
                target_id=str(user_id),
                details={"reason": reason, "sessions_revoked": len(revoked)},
            ),
        )
    for session_id in revoked:
        await sessions.revoke(session_id)
    return StatusChange(user_id, len(revoked))
