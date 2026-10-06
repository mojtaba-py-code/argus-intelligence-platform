"""Document use cases: upload, process (scan, then sandboxed parse), read, download, delete.

Upload stores the encrypted blob, then - in one transaction - the ``documents`` row, the
processing job and the audit record. Processing is a queue task: it verifies the blob's hash,
scans it (a scanner outage retries; it never skips the scan), parses it in the sandbox, and
treats the parser's output as untrusted (re-sanitised, injection-assessed, size-bounded).
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any, Final, Protocol
from uuid import UUID

from sqlalchemy import Select, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.classification import Classification
from argus.core.clock import Clock
from argus.core.config import DocumentSettings, SecuritySettings
from argus.core.crypto import CryptoError, constant_time_equals, sha256
from argus.core.errors import (
    Conflict,
    NotFound,
    PayloadTooLarge,
    PermissionDenied,
    RateLimited,
    ServiceUnavailable,
)
from argus.core.ids import uuid7
from argus.core.logging import get_logger
from argus.core.pagination import Page, PageQuery, encode_cursor
from argus.core.scope import Actor, TenantScope
from argus.infrastructure.db import Database
from argus.infrastructure.malware import MalwareScanner, ScanVerdict
from argus.infrastructure.observability.metrics import Metrics
from argus.infrastructure.queue import JobQueue, JobSpec
from argus.infrastructure.storage import ObjectNotFound
from argus.modules.audit.service import AuditCategory, AuditEvent, AuditOutcome, AuditService
from argus.modules.documents.models import DOWNLOADABLE, Document
from argus.modules.documents.schemas import DocumentDetail, DocumentResponse, DownloadLinkResponse
from argus.modules.documents.validation import clean_filename, decide_kind
from argus.modules.platform import quotas
from argus.modules.tenancy.authorization import ProjectAccess
from argus.modules.tenancy.corpus import bump_corpus_version
from argus.security.injection import assess
from argus.security.links import InvalidLink, issue_link_token, verify_link_token
from argus.security.parsing import ParsedDocument, ParseError, SandboxedParser
from argus.security.permissions import Permission
from argus.security.principals import ClientInfo
from argus.security.ratelimit import POLICIES, RateLimiter
from argus.security.sealed import SealedStore
from argus.security.text import clean_line, sanitize_text

log = get_logger(__name__)
PROCESS_TASK: Final = "documents.process"
DELETE_BLOB_TASK: Final = "storage.delete"
LINK_PURPOSE: Final = "document-download"
_MAX_DETAILS_BYTES: Final = 64 * 1024
# Parser failures that may indicate an exploit attempt rather than a merely broken file.
_SUSPICIOUS_PARSE_FAILURES: Final = frozenset(
    {"timeout", "resource_limit", "memory_limit", "parser_crashed", "output_too_large"}
)


class DocumentIndexer(Protocol):
    """Makes a parsed document searchable (implemented by the knowledge module)."""

    async def index_document(self, organization_id: UUID, document_id: UUID) -> int: ...


def storage_key(organization_id: UUID, project_id: UUID, document_id: UUID) -> str:
    return f"org/{organization_id}/project/{project_id}/documents/{document_id}"


@dataclass(frozen=True)
class DocumentDependencies:
    database: Database
    blobs: SealedStore
    scanner: MalwareScanner
    parser: SandboxedParser
    queue: JobQueue
    audit: AuditService
    limiter: RateLimiter
    clock: Clock
    metrics: Metrics
    settings: DocumentSettings
    security: SecuritySettings
    max_upload_bytes: int
    signing_key: bytes
    link_ttl_s: int
    public_base_url: str
    indexer: DocumentIndexer | None = None


@dataclass(frozen=True)
class DownloadableFile:
    content: bytes
    filename: str
    media_type: str


@dataclass(frozen=True)
class LinkClaims:
    organization_id: UUID
    project_id: UUID
    document_id: UUID
    user_id: UUID
    session_id: UUID
    amr: tuple[str, ...]


def _clean_value(value: Any, depth: int = 0) -> Any:
    """JSON-safe for PostgreSQL: no NUL/control characters, no NaN/Infinity, bounded nesting."""
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if depth >= 6:
        return None
    if isinstance(value, dict):
        return {
            sanitize_text(str(key), max_chars=100).text: _clean_value(item, depth + 1)
            for key, item in list(value.items())[:200]
        }
    if isinstance(value, list | tuple):
        return [_clean_value(item, depth + 1) for item in value[:5000]]
    return sanitize_text(str(value), max_chars=2000).text


def _bounded_details(metadata: dict[str, Any]) -> dict[str, Any]:
    """Parser metadata is untrusted: keep it JSON-safe and small."""
    cleaned: dict[str, Any] = _clean_value(metadata)
    if len(json.dumps(cleaned)) <= _MAX_DETAILS_BYTES:
        return cleaned
    return {k: v for k, v in cleaned.items() if isinstance(v, int | float | bool) or v is None}


class DocumentService:
    def __init__(self, deps: DocumentDependencies) -> None:
        self._d = deps

    # ---------------------------------------------------------------------- helpers
    @staticmethod
    def _visible(access: ProjectAccess, stmt: Select[Document]) -> Select[Document]:
        stmt = stmt.where(
            Document.organization_id == access.org.organization_id,
            Document.project_id == access.project_id,
        )
        if not access.can(Permission.DOCUMENTS_READ_RESTRICTED):
            stmt = stmt.where(Document.classification < int(Classification.RESTRICTED))
        return stmt

    async def _load(
        self, session: AsyncSession, access: ProjectAccess, document_id: UUID
    ) -> Document:
        document = (
            await session.execute(
                self._visible(access, select(Document).where(Document.id == document_id))
            )
        ).scalar_one_or_none()
        if document is None:
            raise NotFound
        return document

    def _event(
        self,
        access: ProjectAccess,
        action: str,
        document_id: UUID,
        client: ClientInfo,
        **details: Any,
    ) -> AuditEvent:
        return AuditEvent(
            action=action,
            category=AuditCategory.DATA_ACCESS,
            actor=access.scope.actor,
            organization_id=access.org.organization_id,
            target_type="document",
            target_id=str(document_id),
            client=client,
            details=details,
        )

    async def _set(self, scope: TenantScope, document_id: UUID, **values: Any) -> None:
        async with self._d.database.tenant(scope) as session:
            await session.execute(
                update(Document)
                .where(Document.id == document_id)
                .values(updated_at=self._d.clock.now(), **values)
            )

    # ----------------------------------------------------------------------- upload
    async def upload(
        self,
        access: ProjectAccess,
        *,
        filename: str | None,
        declared_type: str | None,
        data: bytes,
        classification: Classification | None,
        client: ClientInfo,
    ) -> tuple[DocumentResponse, bool]:
        """Returns ``(document, created)``; identical content in the project is not stored twice."""
        access.require(Permission.DOCUMENTS_UPLOAD)
        if len(data) > self._d.max_upload_bytes:
            raise PayloadTooLarge(
                f"Documents may be at most {self._d.max_upload_bytes // (1024 * 1024)} MB."
            )
        level = (
            classification
            if classification is not None  # PUBLIC is 0: never use "or" here
            else access.org.settings.default_document_classification
        )
        if level >= Classification.RESTRICTED and not access.can(
            Permission.DOCUMENTS_READ_RESTRICTED
        ):
            raise PermissionDenied("You cannot upload documents you would not be allowed to read.")
        decision = await self._d.limiter.hit(
            POLICIES["documents.upload.org"], str(access.org.organization_id)
        )
        if not decision.allowed:
            raise RateLimited(decision.retry_after_s)

        name = clean_filename(filename)
        kind, media_type = decide_kind(name, declared_type, data)
        digest = sha256(data)
        existing = await self._duplicate(access, digest)
        if existing is not None:
            return existing, False

        document_id = uuid7()
        key = storage_key(access.org.organization_id, access.project_id, document_id)
        await self._d.blobs.put(key, data)
        try:
            async with self._d.database.tenant(access.scope) as session:
                await quotas.enforce(
                    session,
                    access.org.organization_id,
                    "storage_bytes",
                    now=self._d.clock.now(),
                    adding=len(data),
                )
                document = Document(
                    id=document_id,
                    organization_id=access.org.organization_id,
                    project_id=access.project_id,
                    filename=name,
                    kind=kind,
                    media_type=media_type,
                    byte_size=len(data),
                    sha256=digest,
                    storage_key=key,
                    classification=int(level),
                    status="pending_scan",
                    created_by=access.org.principal.user_id,
                )
                session.add(document)
                await session.flush()
                await self._d.queue.enqueue(session, self.process_job(document))
                await self._d.audit.record(
                    session,
                    self._event(
                        access,
                        "document.uploaded",
                        document_id,
                        client,
                        kind=kind,
                        bytes=len(data),
                        classification=level.label,
                    ),
                )
                response = DocumentResponse.model_validate(document)
        except IntegrityError:
            await self._discard(key)
            existing = await self._duplicate(access, digest)
            if existing is None:
                raise
            return existing, False
        except BaseException:
            await self._discard(key)
            raise
        self._d.metrics.documents.labels("uploaded").inc()
        return response, True

    async def _duplicate(self, access: ProjectAccess, digest: bytes) -> DocumentResponse | None:
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            document = (
                await session.execute(
                    select(Document).where(
                        Document.organization_id == access.org.organization_id,
                        Document.project_id == access.project_id,
                        Document.sha256 == digest,
                    )
                )
            ).scalar_one_or_none()
        if document is None:
            return None
        if document.classification >= Classification.RESTRICTED and not access.can(
            Permission.DOCUMENTS_READ_RESTRICTED
        ):
            raise Conflict("A document with the same content already exists in this project.")
        return DocumentResponse.model_validate(document)

    async def _discard(self, key: str) -> None:
        try:
            await self._d.blobs.delete(key)
        except Exception:  # noqa: BLE001 - best effort; orphan sweeps catch the rest
            log.warning("documents.orphan_blob", key=key)

    def process_job(self, document: Document) -> JobSpec:
        return JobSpec(
            task=PROCESS_TASK,
            payload={
                "organization_id": str(document.organization_id),
                "document_id": str(document.id),
            },
            queue="documents",
            organization_id=document.organization_id,
            max_attempts=5,
            timeout_s=int(
                self._d.settings.parse_timeout_s + self._d.settings.clamav_timeout_s + 60
            ),
            dedup_key=f"document:{document.id}",
        )

    # ---------------------------------------------------------------------- process
    async def process(self, organization_id: UUID, document_id: UUID) -> str:
        """Queue task body. Idempotent: finished documents are left alone."""
        scope = TenantScope(organization_id, Actor.system())
        async with self._d.database.tenant(scope, read_only=True) as session:
            document = await session.get(Document, document_id)
        if document is None or document.status not in {"pending_scan", "processing"}:
            return document.status if document is not None else "missing"
        try:
            data = await self._d.blobs.get(document.storage_key)
        except ObjectNotFound:
            await self._fail(scope, document, "blob_missing", security=True)
            return "failed"
        except CryptoError:
            await self._fail(scope, document, "integrity_error", security=True)
            return "failed"
        if not constant_time_equals(sha256(data), document.sha256):
            await self._fail(scope, document, "integrity_error", security=True)
            return "failed"
        if document.status == "pending_scan":
            verdict = await self._d.scanner.scan(data)  # ScannerUnavailable -> the job retries
            if not verdict.clean:
                await self._quarantine(scope, document, verdict)
                return "quarantined"
            await self._set(
                scope,
                document.id,
                status="processing",
                scan_engine=verdict.engine,
                scan_signature=None,
                scanned_at=self._d.clock.now(),
            )
        if document.text is None:  # a retry after a successful parse skips straight to indexing
            started = self._d.clock.monotonic()
            try:
                parsed = await self._d.parser.parse(data, document.kind)
            except ParseError as exc:
                self._d.metrics.document_parse.labels(document.kind, "failed").observe(
                    self._d.clock.monotonic() - started
                )
                await self._fail(
                    scope, document, exc.code[:48], security=exc.code in _SUSPICIOUS_PARSE_FAILURES
                )
                return "failed"
            self._d.metrics.document_parse.labels(document.kind, "ok").observe(
                self._d.clock.monotonic() - started
            )
            await self._store_parsed(scope, document, parsed)
        if self._d.indexer is not None:
            # Embedding-provider outages raise here; the job retries and resumes at this step.
            await self._d.indexer.index_document(organization_id, document.id)
        await self._set(scope, document.id, status="ready", processed_at=self._d.clock.now())
        self._d.metrics.documents.labels("ready").inc()
        return "ready"

    async def _store_parsed(
        self, scope: TenantScope, document: Document, parsed: ParsedDocument
    ) -> None:
        # The sandbox's output is untrusted: sanitise and bound it again.
        text = sanitize_text(parsed.text, max_chars=self._d.settings.max_text_chars)
        hidden = sanitize_text(parsed.hidden_text, max_chars=100_000)
        verdict = assess(
            text.text,
            hidden_text=hidden.text,
            invisible_characters=parsed.invisible_characters + text.suspicious_invisible,
            flag_threshold=self._d.security.injection_flag_threshold,
            block_threshold=self._d.security.injection_block_threshold,
        )
        self._d.metrics.injection_detections.labels(verdict.level.value).inc()
        details = {
            "metadata": _bounded_details(parsed.metadata),
            "warnings": [str(w)[:40] for w in parsed.warnings[:20]],
            "created_at": clean_line(parsed.created_at, 64),
            "hidden_text_excerpt": hidden.text[:500] or None,
        }
        await self._set(
            scope,
            document.id,
            error_code=None,
            text=text.text,
            text_chars=len(text.text),
            title=clean_line(parsed.title, 300),
            author=clean_line(parsed.author, 200),
            language=clean_line(parsed.language, 35),
            page_count=parsed.page_count,
            injection_score=verdict.score,
            injection_level=verdict.level.value,
            injection_signals=[
                {"category": s.category, "pattern": s.pattern, "excerpt": s.excerpt[:120]}
                for s in verdict.signals
            ],
            details=details,
        )

    async def _quarantine(
        self, scope: TenantScope, document: Document, verdict: ScanVerdict
    ) -> None:
        async with self._d.database.tenant(scope) as session:
            await session.execute(
                update(Document)
                .where(Document.id == document.id)
                .values(
                    status="quarantined",
                    scan_engine=verdict.engine,
                    scan_signature=verdict.signature,
                    scanned_at=self._d.clock.now(),
                    updated_at=self._d.clock.now(),
                )
            )
            await self._d.audit.record(
                session,
                AuditEvent(
                    action="document.quarantined",
                    category=AuditCategory.SECURITY,
                    actor=scope.actor,
                    outcome=AuditOutcome.FAILURE,
                    organization_id=scope.organization_id,
                    target_type="document",
                    target_id=str(document.id),
                    details={"engine": verdict.engine, "signature": verdict.signature},
                ),
            )
        self._d.metrics.documents.labels("quarantined").inc()
        log.warning(
            "documents.quarantined", document_id=str(document.id), signature=verdict.signature
        )

    async def _fail(
        self, scope: TenantScope, document: Document, code: str, *, security: bool
    ) -> None:
        async with self._d.database.tenant(scope) as session:
            await session.execute(
                update(Document)
                .where(Document.id == document.id)
                .values(
                    status="failed",
                    error_code=code,
                    processed_at=self._d.clock.now(),
                    updated_at=self._d.clock.now(),
                )
            )
            if security:
                await self._d.audit.record(
                    session,
                    AuditEvent(
                        action="document.processing_refused",
                        category=AuditCategory.SECURITY,
                        actor=scope.actor,
                        outcome=AuditOutcome.FAILURE,
                        organization_id=scope.organization_id,
                        target_type="document",
                        target_id=str(document.id),
                        details={"reason": code},
                    ),
                )
        self._d.metrics.documents.labels("failed").inc()

    # ------------------------------------------------------------------------- read
    async def list_documents(
        self, access: ProjectAccess, page: PageQuery, *, status: str | None = None
    ) -> Page[DocumentResponse]:
        access.require(Permission.DOCUMENTS_READ)
        stmt = self._visible(access, select(Document))
        if status is not None:
            stmt = stmt.where(Document.status == status)
        cursor = page.decoded()
        if cursor is not None:
            stmt = stmt.where(
                (Document.created_at < cursor.created_at)
                | ((Document.created_at == cursor.created_at) & (Document.id < cursor.id))
            )
        stmt = stmt.order_by(Document.created_at.desc(), Document.id.desc()).limit(page.limit + 1)
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            rows = list((await session.execute(stmt)).scalars().all())
        next_cursor = None
        if len(rows) > page.limit:
            rows = rows[: page.limit]
            next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id)
        return Page[DocumentResponse](
            items=[DocumentResponse.model_validate(row) for row in rows], next_cursor=next_cursor
        )

    async def get(self, access: ProjectAccess, document_id: UUID) -> DocumentDetail:
        access.require(Permission.DOCUMENTS_READ)
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            document = await self._load(session, access, document_id)
        detail = DocumentDetail.model_validate(document)
        excerpt = document.text[:4000] if document.text else None
        return detail.model_copy(update={"text_excerpt": excerpt})

    # --------------------------------------------------------------------- download
    async def content(
        self,
        access: ProjectAccess,
        document_id: UUID,
        client: ClientInfo,
        *,
        via_link: bool = False,
    ) -> DownloadableFile:
        access.require(Permission.DOCUMENTS_READ)
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            document = await self._load(session, access, document_id)
        if document.status not in DOWNLOADABLE:
            raise Conflict(
                "This document is not available for download until it has been scanned clean."
            )
        try:
            data = await self._d.blobs.get(document.storage_key)
        except (ObjectNotFound, CryptoError) as exc:
            log.error(
                "documents.blob_unreadable", document_id=str(document.id), error=type(exc).__name__
            )
            raise ServiceUnavailable("The document could not be read.") from None
        if not constant_time_equals(sha256(data), document.sha256):
            log.error("documents.integrity_mismatch", document_id=str(document.id))
            raise ServiceUnavailable("The document could not be read.")
        async with self._d.database.tenant(access.scope) as session:
            await self._d.audit.record(
                session,
                self._event(access, "document.downloaded", document.id, client, via_link=via_link),
            )
        # Active content (HTML) is never served with a type a browser could render.
        media_type = "application/octet-stream" if document.kind == "html" else document.media_type
        return DownloadableFile(data, document.filename, media_type)

    async def create_download_link(
        self, access: ProjectAccess, document_id: UUID, client: ClientInfo
    ) -> DownloadLinkResponse:
        access.require(Permission.DOCUMENTS_READ)
        principal = access.org.principal
        if principal.user_id is None or principal.session_id is None:
            raise PermissionDenied(
                "Download links are for signed-in users; API clients download through the content endpoint."
            )
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            document = await self._load(session, access, document_id)
        if document.status not in DOWNLOADABLE:
            raise Conflict(
                "This document is not available for download until it has been scanned clean."
            )
        token, expires_at = issue_link_token(
            {
                "o": str(access.org.organization_id),
                "p": str(access.project_id),
                "d": str(document.id),
                "u": str(principal.user_id),
                "s": str(principal.session_id),
                "m": list(principal.amr),
            },
            key=self._d.signing_key,
            purpose=LINK_PURPOSE,
            now=self._d.clock.now(),
            ttl_s=self._d.link_ttl_s,
        )
        async with self._d.database.tenant(access.scope) as session:
            await self._d.audit.record(
                session, self._event(access, "document.download_link_created", document.id, client)
            )
        return DownloadLinkResponse(
            url=f"{self._d.public_base_url.rstrip('/')}/api/v1/downloads/{token}",
            expires_at=expires_at,
        )

    def verify_link(self, token: str) -> LinkClaims:
        claims = verify_link_token(
            token, key=self._d.signing_key, purpose=LINK_PURPOSE, now=self._d.clock.now()
        )
        try:
            return LinkClaims(
                organization_id=UUID(claims["o"]),
                project_id=UUID(claims["p"]),
                document_id=UUID(claims["d"]),
                user_id=UUID(claims["u"]),
                session_id=UUID(claims["s"]),
                amr=tuple(str(item) for item in claims.get("m", [])),
            )
        except (KeyError, TypeError, ValueError):
            raise InvalidLink from None

    # ----------------------------------------------------------------------- delete
    async def delete(self, access: ProjectAccess, document_id: UUID, client: ClientInfo) -> None:
        access.require(Permission.DOCUMENTS_DELETE)
        async with self._d.database.tenant(access.scope) as session:
            document = await self._load(session, access, document_id)
            key = document.storage_key
            await session.delete(document)  # chunks and embeddings cascade in this transaction
            await session.flush()
            await bump_corpus_version(session, access.project_id)
            await self._d.queue.enqueue(
                session,
                JobSpec(
                    task=DELETE_BLOB_TASK,
                    payload={"organization_id": str(access.org.organization_id), "key": key},
                    queue="default",
                    organization_id=access.org.organization_id,
                    max_attempts=10,
                    timeout_s=60,
                    dedup_key=f"blob-delete:{key}",
                ),
            )
            await self._d.audit.record(
                session, self._event(access, "document.deleted", document_id, client)
            )
        self._d.metrics.documents.labels("deleted").inc()

    async def delete_blob(self, organization_id: UUID, key: str) -> None:
        if not key.startswith(f"org/{organization_id}/"):
            msg = "storage key outside the organisation's prefix"
            raise ValueError(msg)
        await self._d.blobs.delete(key)

    # ------------------------------------------------------------- web content (PDF)
    async def parse_untrusted(self, data: bytes, kind: str) -> ParsedDocument:
        """Sandboxed parse for binary web content (no storage); used by source collection."""
        return await self._d.parser.parse(data, kind)
