"""Organisation lifecycle: plans, suspension, deletion and the purge after the grace period.

States: ``active`` ⇄ ``suspended`` (members get 403, API keys are refused, monitors stop);
``active`` → ``pending_deletion`` (an owner deletes: members lose access at once, API keys are
revoked) → ``purging`` after ``platform.deletion_grace_days`` unless an operator restores it
first → gone.

The purge marks the organisation ``purging`` in its own transaction before anything is deleted:
from that moment it can no longer be restored (its files are about to disappear), and a purge
interrupted half-way is finished by the next run. It then removes the encrypted blobs in object
storage and deletes the organisation row - every tenant table follows through same-tenant
foreign keys with ``ON DELETE CASCADE`` (documents, chunks and vectors, sources and snapshots,
research jobs, findings, reports, monitors, notifications, keys, members, queue jobs...). The
audit chain is the one thing that stays: audit history outlives the tenant by design, and the
purge is recorded in the platform chain.

Operator actions use the owner-role database (``argus orgs``); the scheduled purge uses the
runtime role and a narrow SECURITY DEFINER function that returns due organisation ids only.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal
from uuid import UUID

from sqlalchemy import func, select, text, update

from argus.core.clock import Clock
from argus.core.config import PlatformSettings
from argus.core.logging import get_logger
from argus.core.scope import Actor
from argus.infrastructure.db import Database
from argus.infrastructure.storage import ObjectStore
from argus.modules.audit.service import AuditCategory, AuditEvent, AuditService
from argus.modules.platform.plans import PLANS, PlanName
from argus.modules.tenancy.models import Organization, OrganizationMember

log = get_logger(__name__)
Status = Literal["active", "suspended", "pending_deletion", "purging"]
_DUE = text("SELECT organization_id FROM argus_organizations_due_for_purge(:before, :max_rows)")
_BLOBS = text(
    "SELECT storage_key FROM documents WHERE organization_id = :org"
    " UNION ALL SELECT storage_key FROM organization_exports"
    " WHERE organization_id = :org AND storage_key IS NOT NULL"
)


class LifecycleError(ValueError):
    pass


@dataclass(frozen=True)
class OrganizationRow:
    id: UUID
    slug: str
    name: str
    status: str
    plan: str
    members: int
    created_at: datetime
    deletion_requested_at: datetime | None


class OrganizationLifecycle:
    def __init__(
        self,
        database: Database,
        audit: AuditService,
        storage: ObjectStore,
        clock: Clock,
        settings: PlatformSettings,
    ) -> None:
        self._db = database
        self._audit = audit
        self._storage = storage
        self._clock = clock
        self._settings = settings

    # ------------------------------------------------------------------ operator view
    async def list(self) -> list[OrganizationRow]:
        """Every organisation (owner role: row-level security does not hide any)."""
        members = (
            select(func.count())
            .select_from(OrganizationMember)
            .where(OrganizationMember.organization_id == Organization.id)
            .scalar_subquery()
        )
        async with self._db.session(read_only=True) as session:
            rows = (
                await session.execute(
                    select(
                        Organization.id,
                        Organization.slug,
                        Organization.name,
                        Organization.status,
                        Organization.plan,
                        members.label("members"),
                        Organization.created_at,
                        Organization.deletion_requested_at,
                    ).order_by(Organization.created_at)
                )
            ).all()
        return [OrganizationRow(**row._mapping) for row in rows]

    # ------------------------------------------------------------------ state changes
    async def set_plan(self, organization_id: UUID, plan_name: str, *, reason: str) -> None:
        if plan_name not in PLANS:
            msg = f"plan must be one of {', '.join(PLANS)}"
            raise LifecycleError(msg)
        await self._change(organization_id, "org.plan_changed", reason, plan=plan_name)

    async def suspend(self, organization_id: UUID, *, reason: str) -> None:
        await self._change(
            organization_id, "org.suspended", reason, status="suspended", require="active"
        )

    async def resume(self, organization_id: UUID, *, reason: str) -> None:
        await self._change(
            organization_id, "org.resumed", reason, status="active", require="suspended"
        )

    async def restore(self, organization_id: UUID, *, reason: str) -> None:
        """Cancel a deletion within the grace period (API keys revoked at deletion stay revoked)."""
        await self._change(
            organization_id,
            "org.deletion_cancelled",
            reason,
            status="active",
            require="pending_deletion",
            clear_deletion=True,
        )

    async def _change(
        self,
        organization_id: UUID,
        action: str,
        reason: str,
        *,
        status: Status | None = None,
        plan: str | None = None,
        require: Status | None = None,
        clear_deletion: bool = False,
    ) -> None:
        reason = " ".join(reason.split())[:300]
        if len(reason) < 3:
            msg = "give a reason of at least 3 characters (it is kept in the audit log)"
            raise LifecycleError(msg)
        values: dict[str, object] = {"updated_at": self._clock.now()}
        if status is not None:
            values["status"] = status
        if plan is not None:
            values["plan"] = plan
        if clear_deletion:
            values["deletion_requested_at"] = None
        conditions = [Organization.id == organization_id]
        if require is not None:
            conditions.append(Organization.status == require)
        async with self._db.session(organization_id=organization_id) as session:
            changed = (
                await session.execute(
                    update(Organization)
                    .where(*conditions)
                    .values(**values)
                    .returning(Organization.id)
                )
            ).scalar_one_or_none()
            if changed is None:
                msg = f"no organisation {organization_id}" + (
                    f" in state {require}" if require else ""
                )
                raise LifecycleError(msg)
            await self._audit.record(
                session,
                AuditEvent(
                    action=action,
                    category=AuditCategory.ADMINISTRATION,
                    actor=Actor.system(),
                    organization_id=organization_id,
                    target_type="organization",
                    target_id=str(organization_id),
                    details={"reason": reason, **({"plan": plan} if plan else {})},
                ),
            )

    # ------------------------------------------------------------------------- purge
    async def purge(self, organization_id: UUID, *, force: bool = False) -> int:
        """Delete an organisation pending deletion, with its blobs; returns the blobs removed.

        Before the grace period has passed, only with ``force`` (an operator decision). An
        organisation already ``purging`` (an earlier run stopped half-way) is finished."""
        cutoff = self._clock.now() - timedelta(days=self._settings.deletion_grace_days)
        async with self._db.session(organization_id=organization_id) as session:
            org = (
                await session.execute(
                    select(Organization.status, Organization.deletion_requested_at)
                    .where(Organization.id == organization_id)
                    .with_for_update()
                )
            ).one_or_none()
            if org is None or org.status not in {"pending_deletion", "purging"}:
                msg = "only an organisation pending deletion can be purged"
                raise LifecycleError(msg)
            if org.status == "pending_deletion":
                due = org.deletion_requested_at is not None and org.deletion_requested_at <= cutoff
                if not due and not force:
                    msg = "the grace period has not passed (use force to purge now)"
                    raise LifecycleError(msg)
                # Point of no return, committed before any blob is touched: a restore racing
                # with this purge waits for the row lock and then finds nothing to restore.
                await session.execute(
                    update(Organization)
                    .where(Organization.id == organization_id)
                    .values(status="purging", updated_at=self._clock.now())
                )
                await self._audit.record(
                    session,
                    AuditEvent(
                        action="org.purge_started",
                        category=AuditCategory.ADMINISTRATION,
                        actor=Actor.system(),
                        organization_id=organization_id,
                        target_type="organization",
                        target_id=str(organization_id),
                        details={"forced": force},
                    ),
                )
            keys = [
                str(key)
                for key in (await session.execute(_BLOBS, {"org": organization_id})).scalars()
            ]
        # Deleting a missing blob succeeds, so a resumed purge simply goes over the list again.
        for key in keys:
            await self._storage.delete(key)
        async with self._db.session(organization_id=organization_id) as session:
            deleted = (
                await session.execute(
                    text(
                        "DELETE FROM organizations WHERE id = :org AND status = 'purging'"
                        " RETURNING id"
                    ),
                    {"org": organization_id},
                )
            ).first()
        if deleted is None:
            msg = f"organisation {organization_id} was not purged: it changed meanwhile"
            raise LifecycleError(msg)
        async with self._db.session() as session:
            await self._audit.record(
                session,
                AuditEvent(
                    action="org.purged",
                    category=AuditCategory.ADMINISTRATION,
                    actor=Actor.system(),
                    target_type="organization",
                    target_id=str(organization_id),
                    details={"blobs": len(keys), "forced": force},
                ),
            )
        log.info("organization.purged", organization_id=str(organization_id), blobs=len(keys))
        return len(keys)

    async def purge_due(self, *, limit: int = 20) -> int:
        cutoff = self._clock.now() - timedelta(days=self._settings.deletion_grace_days)
        async with self._db.session(read_only=True) as session:
            due = list(
                (await session.execute(_DUE, {"before": cutoff, "max_rows": limit})).scalars()
            )
        purged = 0
        for organization_id in due:
            try:
                await self.purge(organization_id)
                purged += 1
            except Exception as exc:  # noqa: BLE001 - retried on the next pass
                log.error(
                    "organization.purge_failed",
                    organization_id=str(organization_id),
                    error_type=type(exc).__name__,
                )
        return purged


__all__ = ["LifecycleError", "OrganizationLifecycle", "OrganizationRow", "PlanName"]
