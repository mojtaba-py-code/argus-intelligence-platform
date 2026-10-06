"""Scheduled verification of every organisation's audit chain.

The audit log is append-only in three ways (no UPDATE/DELETE grant, a trigger, an HMAC chain);
the chain only helps if someone *checks* it. This job does, for each organisation, at least
once per ``security.audit_verify_interval_h``:

1. the scheduler asks a narrow SECURITY DEFINER function which organisations are due - it
   returns identifiers only, so the runtime role still cannot read other tenants' data;
2. each chain is recomputed inside that organisation's own row-level-security context, in a
   snapshot transaction (concurrent appends can never look like tampering);
3. the result is stored; a *newly* broken chain is written to the audit log and every owner and
   administrator is alerted in-app and by e-mail. The same break is not re-announced daily.

The platform chain (logins, registrations) belongs to no tenant: operators verify it with
``argus audit verify``, which runs on the owner role and checks every chain.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Final
from uuid import UUID

from sqlalchemy import delete, select, text

from argus.core.clock import Clock
from argus.core.config import SecuritySettings
from argus.core.events import Event, EventSink
from argus.core.ids import uuid7
from argus.core.logging import get_logger
from argus.core.scope import Actor
from argus.infrastructure.db import Database
from argus.infrastructure.observability.metrics import Metrics
from argus.modules.audit.service import (
    AuditCategory,
    AuditEvent,
    AuditOutcome,
    AuditService,
    ChainVerification,
)
from argus.modules.security_center.models import REASONS, AuditVerification
from argus.modules.security_center.schemas import AuditVerificationResponse

log = get_logger(__name__)
SECURITY_LINK: Final = "/security"
_DUE = text("SELECT organization_id FROM argus_audit_verification_due(:max_rows, :verified_before)")
_ADMINS = text(
    "SELECT user_id FROM organization_members"
    " WHERE organization_id = :org AND role IN ('owner', 'admin') ORDER BY user_id"
)


@dataclass(frozen=True)
class IntegrityDependencies:
    database: Database
    audit: AuditService
    events: EventSink
    clock: Clock
    metrics: Metrics
    settings: SecuritySettings


class AuditIntegrity:
    def __init__(self, deps: IntegrityDependencies) -> None:
        self._d = deps

    async def verify(
        self, organization_id: UUID, *, trigger: str, requested_by: UUID | None = None
    ) -> AuditVerificationResponse:
        d = self._d
        started = time.monotonic()
        async with d.database.session(
            organization_id=organization_id, read_only=True, snapshot=True
        ) as session:
            result = await d.audit.verify_chain(session, str(organization_id))
        duration_ms = int((time.monotonic() - started) * 1000)
        reason = self._known_reason(result)
        now = d.clock.now()
        row = AuditVerification(
            id=uuid7(),
            organization_id=organization_id,
            verified_at=now,
            trigger=trigger,
            valid=result.valid,
            events=result.events,
            first_broken_seq=None if result.valid else result.first_broken_seq,
            reason=reason,
            duration_ms=duration_ms,
            requested_by=requested_by,
        )
        admins: tuple[UUID, ...] = ()
        async with d.database.session(organization_id=organization_id) as session:
            previous = (
                await session.execute(
                    select(AuditVerification)
                    .where(AuditVerification.organization_id == organization_id)
                    .order_by(AuditVerification.verified_at.desc(), AuditVerification.id.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            session.add(row)
            await session.flush()
            await session.execute(
                delete(AuditVerification).where(
                    AuditVerification.organization_id == organization_id,
                    AuditVerification.verified_at
                    < now - timedelta(days=d.settings.audit_verification_retention_days),
                )
            )
            newly_broken = not result.valid and (
                previous is None
                or previous.valid
                or (previous.first_broken_seq, previous.reason) != (row.first_broken_seq, reason)
            )
            if newly_broken:
                admins = tuple(
                    (await session.execute(_ADMINS, {"org": organization_id})).scalars().all()
                )
        if newly_broken:
            # In its own transaction: whoever broke the chain may also have made appends fail
            # (a forged row occupying the next sequence number), and that must not erase the
            # verification result or stop the alert.
            await d.audit.record_detached(
                AuditEvent(
                    action="audit.integrity_failed",
                    category=AuditCategory.SECURITY,
                    actor=Actor.system(),
                    outcome=AuditOutcome.FAILURE,
                    organization_id=organization_id,
                    target_type="audit_chain",
                    target_id=str(organization_id),
                    details={"first_broken_seq": row.first_broken_seq, "reason": reason},
                )
            )
        d.metrics.audit_verifications.labels("valid" if result.valid else "broken").inc()
        if result.valid:
            log.info("audit.chain_verified", events=result.events, duration_ms=duration_ms)
        else:
            log.error(
                "audit.chain_broken",
                organization_id=str(organization_id),
                first_broken_seq=row.first_broken_seq,
                reason=reason,
            )
        if newly_broken:
            await d.events.emit(
                Event(
                    type="security.audit.integrity_failed",
                    organization_id=organization_id,
                    title="Audit log integrity check failed",
                    body=(
                        f"The audit log failed verification at event {row.first_broken_seq}"
                        f" ({reason}). Records may have been changed outside the application."
                        " Contact your platform operator and keep the database unchanged for"
                        " the investigation."
                    ),
                    link=SECURITY_LINK,
                    recipients=admins,
                    email=True,
                    data={"first_broken_seq": row.first_broken_seq, "reason": reason},
                )
            )
        return AuditVerificationResponse.model_validate(row)

    async def verify_due(self) -> int:
        """Verify the organisations whose last check is older than the interval (one batch)."""
        d = self._d
        cutoff = d.clock.now() - timedelta(hours=d.settings.audit_verify_interval_h)
        async with d.database.session() as session:
            due = list(
                (
                    await session.execute(
                        _DUE, {"max_rows": d.settings.audit_verify_batch, "verified_before": cutoff}
                    )
                ).scalars()
            )
        verified = 0
        for organization_id in due:
            try:
                await self.verify(organization_id, trigger="scheduled")
                verified += 1
            except Exception as exc:  # noqa: BLE001 - one tenant's failure must not stop the rest
                log.error(
                    "audit.verification_failed",
                    organization_id=str(organization_id),
                    error_type=type(exc).__name__,
                )
        return verified

    @staticmethod
    def _known_reason(result: ChainVerification) -> str | None:
        """The reason as one of the fixed phrases (it is shown in alerts and dashboards)."""
        if result.valid:
            return None
        return result.reason if result.reason in REASONS else "verification failed"
