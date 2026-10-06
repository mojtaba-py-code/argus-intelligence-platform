"""Organisation data export (spec §41: export): everything an organisation owns, in one archive.

* **Owners only** (``org:export``, never delegable to API keys); requested through the API, built
  by a worker, downloaded through the API - re-authorised at every step, audited, rate-limited.
* **One consistent view**: the archive is read in a single snapshot transaction inside the
  organisation's row-level-security context, so it can never contain another tenant's rows.
* **Explicit columns**: secrets and internals never leave (password and key hashes, token hashes,
  embeddings, search vectors); API keys appear as metadata only.
* **Safe archive**: entry names are generated (ids and a sanitised file name), never taken from
  user input as paths, so extracting it cannot write outside its directory.
* **Encrypted at rest** like documents (``SealedStore``) and deleted after
  ``platform.export_ttl_days``.
* **Bounded**: one export in preparation per organisation (a unique index, so concurrent requests
  cannot both start one), included documents capped, the archive kept below the single-object
  encryption limit, and at most ``DOWNLOAD_SLOTS`` archives decrypted at once per API process.

Layout (``argus.export/1``): ``manifest.json``, one JSON-lines file per table, ``reports/<job>.md``,
``documents/<id>/<name>`` and ``audit.jsonl`` (the organisation's audit chain). Documents are the
originals that passed scanning - never quarantined or unscanned files - up to
``platform.export_max_document_bytes`` in total; beyond that the export lists them, and an
unreadable one is listed in the manifest instead of failing the export. The manifest carries the
chain's verification and, for a pruned chain, the signed checkpoint it starts from, so the copy
can be re-verified offline with the audit key.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Final
from uuid import UUID

from pydantic import BaseModel
from sqlalchemy import bindparam, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.clock import Clock
from argus.core.config import PlatformSettings
from argus.core.errors import Conflict, NotFound, RateLimited
from argus.core.events import Event, EventSink
from argus.core.ids import uuid7
from argus.core.logging import get_logger
from argus.infrastructure.db import Database
from argus.infrastructure.queue import JobQueue, JobSpec
from argus.modules.audit.models import AuditLog
from argus.modules.audit.service import AuditCategory, AuditEvent, AuditService
from argus.modules.documents.models import DOWNLOADABLE
from argus.modules.platform.models import OrganizationExport
from argus.modules.tenancy.authorization import OrgAccess
from argus.modules.tenancy.models import Organization, OrganizationMember
from argus.security.principals import ClientInfo
from argus.security.ratelimit import POLICIES, RateLimiter
from argus.security.sealed import SealedStore

log = get_logger(__name__)
EXPORT_TASK: Final = "platform.export"
FORMAT: Final = "argus.export/1"
# Two attempts of at most an hour each: a "pending" export older than this was lost with its job.
STALE_AFTER: Final = timedelta(hours=3)
# AES-GCM seals one object in one call (at most 2**31 - 1 bytes); stay well below it.
MAX_ARCHIVE_BYTES: Final = 1536 * 1024 * 1024
# Decrypting and hashing an archive needs a few times its size in memory: bound it per process.
DOWNLOAD_SLOTS: Final = 2
type SkippedDocuments = list[dict[str, str]]
_UNSAFE_NAME: Final = re.compile(r"[^A-Za-z0-9._-]+")
TABLES: Final[tuple[tuple[str, str], ...]] = (
    (
        "members.jsonl",
        (
            "SELECT m.user_id, u.email, u.full_name, m.role, m.created_at AS joined_at"
            " FROM organization_members m JOIN users u ON u.id = m.user_id"
            " WHERE m.organization_id = :org ORDER BY m.created_at, m.user_id"
        ),
    ),
    (
        "projects.jsonl",
        (
            "SELECT id, name, description, visibility, created_at FROM projects"
            " WHERE organization_id = :org ORDER BY created_at, id"
        ),
    ),
    (
        "research_jobs.jsonl",
        (
            "SELECT id, project_id, title, objective, mode, status, budget_usd, spent_usd,"
            " input_tokens, output_tokens, error_code, created_at, started_at, finished_at"
            " FROM research_jobs WHERE organization_id = :org ORDER BY created_at, id"
        ),
    ),
    (
        "findings.jsonl",
        (
            "SELECT id, job_id, question_id, ordinal, statement, kind, confidence, support,"
            " support_rationale, evidence_classification, created_at FROM research_findings"
            " WHERE organization_id = :org ORDER BY job_id, ordinal, id"
        ),
    ),
    (
        "citations.jsonl",
        (
            "SELECT finding_id, chunk_id, ref, quote, verified FROM research_citations"
            " WHERE organization_id = :org ORDER BY finding_id, ref"
        ),
    ),
    (
        "contradictions.jsonl",
        (
            "SELECT id, job_id, finding_a_id, finding_b_id, attribute, explanation, rationale,"
            " preferred, created_at FROM research_contradictions"
            " WHERE organization_id = :org ORDER BY job_id, created_at, id"
        ),
    ),
    (
        "reports.jsonl",
        (
            "SELECT job_id, version, content, quality, evidence_classification, created_at"
            " FROM research_reports WHERE organization_id = :org ORDER BY job_id, version"
        ),
    ),
    (
        "sources.jsonl",
        (
            "SELECT id, project_id, url, domain, status, title, author, publisher, published_at,"
            " trust_tier, injection_level, discovered_via, created_at, last_fetched_at"
            " FROM sources WHERE organization_id = :org ORDER BY created_at, id"
        ),
    ),
    (
        "source_snapshots.jsonl",
        (
            "SELECT DISTINCT ON (source_id) id, source_id, fetched_at, last_seen_at, final_url,"
            " title, text, injection_level FROM source_snapshots WHERE organization_id = :org"
            " ORDER BY source_id, last_seen_at DESC, fetched_at DESC"
        ),
    ),
    (
        "documents.jsonl",
        (
            "SELECT id, project_id, filename, kind, media_type, byte_size,"
            " encode(sha256, 'hex') AS sha256, classification, status, title, author, language,"
            " page_count, created_at FROM documents WHERE organization_id = :org"
            " ORDER BY created_at, id"
        ),
    ),
    (
        "monitors.jsonl",
        (
            "SELECT id, project_id, name, kind, queries, topics, interval_minutes,"
            " significance_threshold, status, created_at, last_run_at FROM monitors"
            " WHERE organization_id = :org ORDER BY created_at, id"
        ),
    ),
    (
        "monitor_changes.jsonl",
        (
            "SELECT id, monitor_id, target_id, topics, significance, summary, diff, status,"
            " created_at FROM monitor_changes WHERE organization_id = :org ORDER BY created_at, id"
        ),
    ),
    (
        "domain_policies.jsonl",
        (
            "SELECT domain, policy, reputation_override, note, created_at FROM domain_policies"
            " WHERE organization_id = :org ORDER BY domain"
        ),
    ),
    (
        "api_keys.jsonl",
        (
            "SELECT id, key_id, name, scopes, expires_at, last_used_at, revoked_at, created_at"
            " FROM api_keys WHERE organization_id = :org ORDER BY created_at, id"
        ),
    ),
)


class ExportResponse(BaseModel):
    id: UUID
    status: str
    byte_size: int | None
    sha256: str | None
    documents_included: bool | None
    error_code: str | None
    created_at: datetime
    completed_at: datetime | None
    expires_at: datetime


@dataclass(frozen=True)
class ExportDownload:
    content: bytes
    filename: str


@dataclass(frozen=True)
class ExportDependencies:
    database: Database
    blobs: SealedStore
    queue: JobQueue
    audit: AuditService
    events: EventSink
    limiter: RateLimiter
    clock: Clock
    settings: PlatformSettings


def _json(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    if isinstance(value, UUID | Decimal):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    msg = f"unexpected value of type {type(value).__name__}"
    raise TypeError(msg)


def _line(record: dict[str, Any]) -> bytes:
    return (json.dumps(record, default=_json, ensure_ascii=False, sort_keys=True) + "\n").encode()


def safe_name(filename: str) -> str:
    """A file name that cannot be a path: no separators, no leading dots, bounded."""
    name = _UNSAFE_NAME.sub("_", filename).lstrip("._")[:100]
    return name or "document"


def _response(row: OrganizationExport) -> ExportResponse:
    return ExportResponse(
        id=row.id,
        status=row.status,
        byte_size=row.byte_size,
        sha256=row.sha256.hex() if row.sha256 is not None else None,
        documents_included=row.documents_included,
        error_code=row.error_code,
        created_at=row.created_at,
        completed_at=row.completed_at,
        expires_at=row.expires_at,
    )


class ExportService:
    def __init__(self, deps: ExportDependencies) -> None:
        self._d = deps
        self._downloads = asyncio.Semaphore(DOWNLOAD_SLOTS)

    # ------------------------------------------------------------------ request & list
    async def request(self, access: OrgAccess, client: ClientInfo) -> ExportResponse:
        d = self._d
        decision = await d.limiter.hit(POLICIES["exports.create.org"], str(access.organization_id))
        if not decision.allowed:
            raise RateLimited(decision.retry_after_s)
        if access.principal.user_id is None:
            raise Conflict("Exports are requested by a signed-in owner.")
        now = d.clock.now()
        async with d.database.tenant(access.scope) as session:
            await session.execute(
                update(OrganizationExport)
                .where(
                    OrganizationExport.organization_id == access.organization_id,
                    OrganizationExport.status == "pending",
                    OrganizationExport.created_at < now - STALE_AFTER,
                )
                .values(status="failed", error_code="timed_out", completed_at=now)
            )
            active = (
                await session.execute(
                    select(OrganizationExport.id).where(
                        OrganizationExport.organization_id == access.organization_id,
                        OrganizationExport.status == "pending",
                    )
                )
            ).first()
            if active is not None:
                raise Conflict("An export of this organisation is already being prepared.")
            export = OrganizationExport(
                id=uuid7(),
                organization_id=access.organization_id,
                requested_by=access.principal.user_id,
                status="pending",
                created_at=now,
                expires_at=now + timedelta(days=d.settings.export_ttl_days),
            )
            session.add(export)
            try:
                await session.flush()
            except IntegrityError:  # a concurrent request started one first
                raise Conflict(
                    "An export of this organisation is already being prepared."
                ) from None
            await d.queue.enqueue(
                session,
                JobSpec(
                    task=EXPORT_TASK,
                    queue="default",
                    organization_id=access.organization_id,
                    payload={"export_id": str(export.id)},
                    max_attempts=2,
                    timeout_s=3600,
                ),
            )
            await d.audit.record(
                session,
                AuditEvent(
                    action="org.export_requested",
                    category=AuditCategory.DATA_ACCESS,
                    actor=access.scope.actor,
                    organization_id=access.organization_id,
                    target_type="organization_export",
                    target_id=str(export.id),
                    client=client,
                ),
            )
            return _response(export)

    async def list(self, access: OrgAccess) -> list[ExportResponse]:
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            rows = (
                await session.execute(
                    select(OrganizationExport)
                    .where(OrganizationExport.organization_id == access.organization_id)
                    .order_by(OrganizationExport.created_at.desc())
                    .limit(20)
                )
            ).scalars()
            return [_response(row) for row in rows]

    # ----------------------------------------------------------------------- download
    async def download(
        self, access: OrgAccess, export_id: UUID, client: ClientInfo
    ) -> ExportDownload:
        d = self._d
        key = str(access.principal.user_id or access.principal.api_key_id)
        decision = await d.limiter.hit(POLICIES["exports.download.user"], key)
        if not decision.allowed:
            raise RateLimited(decision.retry_after_s)
        async with d.database.tenant(access.scope) as session:
            row = (
                await session.execute(
                    select(OrganizationExport, Organization.slug)
                    .join(Organization, Organization.id == OrganizationExport.organization_id)
                    .where(
                        OrganizationExport.organization_id == access.organization_id,
                        OrganizationExport.id == export_id,
                    )
                )
            ).one_or_none()
            if row is None or row.OrganizationExport.status != "ready":
                raise NotFound
            export = row.OrganizationExport
            if export.expires_at <= d.clock.now() or export.storage_key is None:
                raise NotFound
            await d.audit.record(
                session,
                AuditEvent(
                    action="org.export_downloaded",
                    category=AuditCategory.DATA_ACCESS,
                    actor=access.scope.actor,
                    organization_id=access.organization_id,
                    target_type="organization_export",
                    target_id=str(export.id),
                    client=client,
                ),
            )
        if self._downloads.locked():
            raise RateLimited(30)
        async with self._downloads:
            content = await d.blobs.get(export.storage_key)
            digest = hashlib.sha256(content).digest()
        if export.sha256 is not None and digest != bytes(export.sha256):
            log.error("export.integrity_mismatch", export_id=str(export.id))
            raise NotFound
        stamp = export.created_at.astimezone(UTC).strftime("%Y%m%d")
        return ExportDownload(content, f"argus-export-{row.slug}-{stamp}.zip")

    # -------------------------------------------------------------------------- build
    async def build(
        self, organization_id: UUID, export_id: UUID, *, final_attempt: bool = True
    ) -> str:
        """Worker task. Returns the final status. A failure before the last attempt leaves the
        export pending, so the retry rebuilds it from scratch."""
        d = self._d
        async with d.database.session(organization_id=organization_id, read_only=True) as session:
            export = (
                await session.execute(
                    select(OrganizationExport).where(
                        OrganizationExport.organization_id == organization_id,
                        OrganizationExport.id == export_id,
                    )
                )
            ).scalar_one_or_none()
            if export is None or export.status != "pending":
                return "skipped"
            still_owner = (
                await session.execute(
                    select(OrganizationMember.role).where(
                        OrganizationMember.organization_id == organization_id,
                        OrganizationMember.user_id == export.requested_by,
                    )
                )
            ).scalar_one_or_none() == "owner"
        if not still_owner:
            await self._finish(organization_id, export_id, status="failed", error="access_revoked")
            return "failed"
        key = f"org/{organization_id}/exports/{export_id}"
        try:
            archive, included = await self._archive(organization_id)
            if len(archive) > MAX_ARCHIVE_BYTES:
                await self._finish(organization_id, export_id, status="failed", error="too_large")
                return "failed"
            await d.blobs.put(key, archive)
        except Exception as exc:
            log.error(
                "export.failed",
                export_id=str(export_id),
                error_type=type(exc).__name__,
                final=final_attempt,
            )
            if final_attempt:
                await self._finish(
                    organization_id, export_id, status="failed", error="build_failed"
                )
            raise
        await self._finish(
            organization_id,
            export_id,
            status="ready",
            key=key,
            size=len(archive),
            digest=hashlib.sha256(archive).digest(),
            included=included,
        )
        await d.events.emit(
            Event(
                type="platform.export.ready",
                organization_id=organization_id,
                title="Your organisation export is ready",
                body=(
                    "The archive can be downloaded by an owner until it expires in"
                    f" {d.settings.export_ttl_days} days."
                ),
                link="/settings/exports",
                recipients=(export.requested_by,),
                email=True,
                data={"export_id": str(export_id)},
            )
        )
        return "ready"

    async def _finish(
        self,
        organization_id: UUID,
        export_id: UUID,
        *,
        status: str,
        error: str | None = None,
        key: str | None = None,
        size: int | None = None,
        digest: bytes | None = None,
        included: bool | None = None,
    ) -> None:
        async with self._d.database.session(organization_id=organization_id) as session:
            await session.execute(
                update(OrganizationExport)
                .where(
                    OrganizationExport.organization_id == organization_id,
                    OrganizationExport.id == export_id,
                )
                .values(
                    status=status,
                    error_code=error,
                    storage_key=key,
                    byte_size=size,
                    sha256=digest,
                    documents_included=included,
                    completed_at=self._d.clock.now(),
                )
            )

    async def _archive(self, organization_id: UUID) -> tuple[bytes, bool]:
        d = self._d
        with tempfile.TemporaryFile() as handle:
            with zipfile.ZipFile(handle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                # One snapshot: every file describes the same moment.
                async with d.database.session(
                    organization_id=organization_id, read_only=True, snapshot=True
                ) as session:
                    organization = await self._organization(session, organization_id)
                    for name, sql in TABLES:
                        await self._jsonl(archive, session, name, sql, organization_id)
                    await self._reports(archive, session, organization_id)
                    included, skipped = await self._documents(archive, session, organization_id)
                    verification = await self._audit(archive, session, organization_id)
                manifest = {
                    "format": FORMAT,
                    "generated_at": d.clock.now(),
                    "organization": organization,
                    "documents_included": included,
                    "documents_skipped": skipped,
                    "audit_chain": verification,
                    "files": sorted(info.filename for info in archive.infolist()),
                }
                archive.writestr("manifest.json", json.dumps(manifest, default=_json, indent=2))
            handle.seek(0)
            return handle.read(), included

    @staticmethod
    async def _organization(session: AsyncSession, organization_id: UUID) -> dict[str, Any]:
        org = (
            await session.execute(select(Organization).where(Organization.id == organization_id))
        ).scalar_one()
        return {
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
            "plan": org.plan,
            "status": org.status,
            "settings": org.settings,
            "created_at": org.created_at,
        }

    @staticmethod
    async def _jsonl(
        archive: zipfile.ZipFile,
        session: AsyncSession,
        name: str,
        sql: str,
        organization_id: UUID,
    ) -> None:
        rows = await session.stream(text(sql), {"org": organization_id})
        with archive.open(name, "w") as entry:
            async for row in rows:
                entry.write(_line(dict(row._mapping)))

    @staticmethod
    async def _reports(archive: zipfile.ZipFile, session: AsyncSession, org: UUID) -> None:
        rows = await session.stream(
            text(
                "SELECT DISTINCT ON (job_id) job_id, markdown FROM research_reports"
                " WHERE organization_id = :org ORDER BY job_id, version DESC"
            ),
            {"org": org},
        )
        async for row in rows:
            archive.writestr(f"reports/{row.job_id}.md", row.markdown)

    async def _documents(
        self, archive: zipfile.ZipFile, session: AsyncSession, org: UUID
    ) -> tuple[bool, SkippedDocuments]:
        """The originals a member could download (never quarantined or unscanned files), if
        they fit under the cap. A missing or damaged file is listed, not fatal: one bad blob must
        not make the organisation's data impossible to export."""
        params = {"org": org, "statuses": sorted(DOWNLOADABLE)}
        total = (
            await session.execute(
                text(
                    "SELECT coalesce(sum(byte_size), 0) FROM documents"
                    " WHERE organization_id = :org AND status IN :statuses"
                ).bindparams(bindparam("statuses", expanding=True)),
                params,
            )
        ).scalar_one()
        if int(total) > self._d.settings.export_max_document_bytes:
            return False, []
        rows = await session.stream(
            text(
                "SELECT id, filename, storage_key, sha256 FROM documents"
                " WHERE organization_id = :org AND status IN :statuses ORDER BY created_at, id"
            ).bindparams(bindparam("statuses", expanding=True)),
            params,
        )
        skipped: SkippedDocuments = []
        async for row in rows:
            try:
                content = await self._d.blobs.get(row.storage_key)
            except Exception as exc:  # noqa: BLE001 - listed in the manifest instead
                log.warning(
                    "export.document_unreadable",
                    document_id=str(row.id),
                    error_type=type(exc).__name__,
                )
                skipped.append({"id": str(row.id), "reason": "unreadable"})
                continue
            if hashlib.sha256(content).digest() != bytes(row.sha256):
                log.error("export.document_integrity_mismatch", document_id=str(row.id))
                skipped.append({"id": str(row.id), "reason": "integrity"})
                continue
            archive.writestr(f"documents/{row.id}/{safe_name(row.filename)}", content)
        return True, skipped

    async def _audit(
        self, archive: zipfile.ZipFile, session: AsyncSession, org: UUID
    ) -> dict[str, Any]:
        result = await self._d.audit.verify_chain(session, str(org))
        table = AuditLog.__table__
        rows = await session.stream(
            select(table).where(table.c.chain_key == str(org)).order_by(table.c.chain_seq)
        )
        with archive.open("audit.jsonl", "w") as entry:
            async for row in rows:
                entry.write(_line(dict(row._mapping)))
        return {
            "valid": result.valid,
            "events": result.events,
            "first_broken_seq": result.first_broken_seq,
            "reason": result.reason,
            "checkpoint": await self._d.audit.checkpoint(session, str(org)),
        }
