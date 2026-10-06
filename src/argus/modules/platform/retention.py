"""Retention: organisations' retention settings, enforced (spec §40, §41).

Daily, per organisation (inside its own row-level-security context), in small batches:

* superseded web-page versions older than ``retention.raw_snapshots_days`` - never the current
  version of a source (the one seen most recently: a page that changes back to earlier content
  re-uses that version's row, so "current" is the latest ``last_seen_at``, not the latest
  ``fetched_at``) and never a version a monitor compares against; their chunks, vectors and
  citations go with them;
* monitor changes (diff excerpts of untrusted pages) older than ``retention.monitor_snapshots_days``;
* audit events older than ``retention.audit_days`` (at least 90), behind a signed checkpoint -
  and only when the chain verifies.

Platform-wide: per-call model ledger rows (daily aggregates stay for budgets and reports) and
finished queue jobs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Final
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.sql.elements import TextClause

from argus.core.clock import Clock
from argus.core.config import PlatformSettings
from argus.core.logging import get_logger
from argus.infrastructure.db import Database
from argus.infrastructure.storage import ObjectStore
from argus.modules.audit.service import AuditService
from argus.modules.tenancy.schemas import OrganizationSettings

log = get_logger(__name__)
BATCH: Final = 1_000
_ORGANIZATIONS = text(
    "SELECT organization_id, settings FROM argus_organizations_for_retention(:after, :max_rows)"
)
_SNAPSHOTS = text(
    "DELETE FROM source_snapshots WHERE id IN ("
    " SELECT s.id FROM source_snapshots s"
    " WHERE s.organization_id = :org AND s.last_seen_at < :cutoff"
    " AND EXISTS (SELECT 1 FROM source_snapshots newer"
    "  WHERE newer.organization_id = s.organization_id AND newer.source_id = s.source_id"
    "  AND newer.last_seen_at > s.last_seen_at)"
    " AND NOT EXISTS (SELECT 1 FROM monitor_targets t"
    "  WHERE t.organization_id = s.organization_id AND t.last_snapshot_id = s.id)"
    " LIMIT :batch)"
)
_CHANGES = text(
    "DELETE FROM monitor_changes WHERE id IN (SELECT id FROM monitor_changes"
    " WHERE organization_id = :org AND created_at < :cutoff LIMIT :batch)"
)
_LLM_REQUESTS = text(
    "DELETE FROM llm_requests WHERE id IN (SELECT id FROM llm_requests"
    " WHERE organization_id = :org AND created_at < :cutoff LIMIT :batch)"
)
# RETURNING sees the updated row, so the archive's key is read from the locked old row.
_EXPIRED_EXPORTS = text(
    "UPDATE organization_exports e SET status = 'expired', storage_key = NULL"
    " FROM (SELECT id, storage_key FROM organization_exports"
    "  WHERE organization_id = :org AND status IN ('pending', 'ready', 'failed')"
    "  AND expires_at < :now"
    "  FOR UPDATE) old"
    " WHERE e.id = old.id"
    " RETURNING old.storage_key"
)
_JOBS = text(
    "DELETE FROM jobs WHERE id IN (SELECT id FROM jobs"
    " WHERE status IN ('succeeded', 'failed', 'cancelled') AND finished_at < :cutoff"
    " LIMIT :batch)"
)


@dataclass
class RetentionReport:
    organizations: int = 0
    deleted: dict[str, int] = field(default_factory=dict)

    def add(self, what: str, count: int) -> None:
        if count:
            self.deleted[what] = self.deleted.get(what, 0) + count


class Retention:
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

    async def sweep(self) -> RetentionReport:
        report = RetentionReport()
        after: UUID | None = None
        while True:
            async with self._db.session(read_only=True) as session:
                page = (
                    await session.execute(_ORGANIZATIONS, {"after": after, "max_rows": 200})
                ).all()
            if not page:
                break
            for row in page:
                after = row.organization_id
                try:
                    await self.organization(row.organization_id, row.settings or {}, report)
                    report.organizations += 1
                except Exception as exc:  # noqa: BLE001 - one tenant must not stop the others
                    log.error(
                        "retention.organization_failed",
                        organization_id=str(row.organization_id),
                        error_type=type(exc).__name__,
                    )
        await self._batched(None, _JOBS, self._days(self._settings.finished_jobs_retention_days))
        if report.deleted:
            log.info("retention.swept", **report.deleted, organizations=report.organizations)
        return report

    async def organization(
        self, organization_id: UUID, raw_settings: dict[str, object], report: RetentionReport
    ) -> None:
        retention = OrganizationSettings.model_validate(raw_settings).retention
        report.add(
            "snapshots",
            await self._batched(
                organization_id, _SNAPSHOTS, self._days(retention.raw_snapshots_days)
            ),
        )
        report.add(
            "monitor_changes",
            await self._batched(
                organization_id, _CHANGES, self._days(retention.monitor_snapshots_days)
            ),
        )
        report.add(
            "llm_requests",
            await self._batched(
                organization_id,
                _LLM_REQUESTS,
                self._days(self._settings.llm_requests_retention_days),
            ),
        )
        # The row stops pointing at the archive first (no download can reach it), then the
        # archive goes; a failed delete leaves only a sealed blob, and is logged.
        async with self._db.session(organization_id=organization_id) as session:
            expired = list(
                (
                    await session.execute(
                        _EXPIRED_EXPORTS, {"org": organization_id, "now": self._clock.now()}
                    )
                ).scalars()
            )
        for key in expired:
            if not key:
                continue
            try:
                await self._storage.delete(str(key))
            except Exception as exc:  # noqa: BLE001 - keep expiring the others
                log.error(
                    "retention.export_blob_delete_failed",
                    organization_id=str(organization_id),
                    error_type=type(exc).__name__,
                )
        report.add("exports", len(expired))
        pruned = await self._audit.prune(
            str(organization_id),
            older_than=self._days(retention.audit_days),
            organization_id=organization_id,
        )
        report.add("audit_events", pruned.pruned)

    async def _batched(
        self, organization_id: UUID | None, statement: TextClause, cutoff: datetime
    ) -> int:
        total = 0
        while True:
            async with self._db.session(organization_id=organization_id) as session:
                result = await session.execute(
                    statement, {"org": organization_id, "cutoff": cutoff, "batch": BATCH}
                )
            deleted = int(getattr(result, "rowcount", 0) or 0)
            total += deleted
            if deleted < BATCH:
                return total

    def _days(self, days: int) -> datetime:
        return self._clock.now() - timedelta(days=days)
