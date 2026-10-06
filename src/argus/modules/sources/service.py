"""Source collection: fetch safely, extract, sanitise, assess, and record with provenance.

``collect`` is the single code path for every web page the platform reads - manual additions,
search results, followed links and monitors - so every page gets the same treatment: domain
policy → robots.txt → politeness → SSRF-guarded fetch → extraction (hidden text separated) →
Unicode sanitising → injection assessment → reputation → deduplicated snapshot.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, Protocol
from uuid import UUID

from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.clock import Clock
from argus.core.config import EgressSettings, SecuritySettings
from argus.core.crypto import sha256
from argus.core.errors import NotFound, RateLimited
from argus.core.ids import uuid7
from argus.core.logging import get_logger
from argus.core.pagination import Page, PageQuery, encode_cursor
from argus.core.scope import TenantScope
from argus.infrastructure.db import Database
from argus.infrastructure.observability.metrics import Metrics
from argus.infrastructure.queue import JobQueue, JobSpec
from argus.modules.audit.service import AuditCategory, AuditEvent, AuditService
from argus.modules.sources.models import DomainPolicy, Source, SourceSnapshot
from argus.modules.sources.reputation import ReputationModel, domain_matches
from argus.modules.sources.robots import Politeness, RobotsCache
from argus.modules.sources.schemas import (
    DomainPolicyRequest,
    DomainPolicyResponse,
    SnapshotDetail,
    SnapshotSummary,
    SourceDetail,
    SourceResponse,
)
from argus.modules.tenancy.authorization import OrgAccess, ProjectAccess
from argus.security.fetcher import DOCUMENT_TYPES, TEXT_TYPES, FetchError, FetchResult, SafeFetcher
from argus.security.html import HTMLTooComplex, extract_html
from argus.security.injection import assess
from argus.security.parsing import ParseError, SandboxedParser
from argus.security.permissions import Permission
from argus.security.principals import ClientInfo
from argus.security.ratelimit import POLICIES, RateLimiter
from argus.security.ssrf import SafeURL, parse_url
from argus.security.text import clean_line, sanitize_text

log = get_logger(__name__)
FETCH_TASK = "sources.fetch"
MAX_TEXT_CHARS = 2_000_000
Discovery = Literal["manual", "search", "link", "monitor"]


@dataclass(frozen=True)
class CollectOutcome:
    source_id: UUID
    status: Literal["fetched", "failed", "blocked", "needs_approval"]
    snapshot_id: UUID | None = None
    new_content: bool = False
    error_code: str | None = None
    injection_level: str = "none"
    title: str | None = None
    media_type: str | None = None


@dataclass
class ExtractedContent:
    title: str | None
    text: str
    details: dict[str, Any]
    hidden_text: str = ""
    invisible: int = 0
    author: str | None = None
    publisher: str | None = None
    published_at: datetime | None = None
    language: str | None = None


class SnapshotIndexer(Protocol):
    """Makes a source's current content searchable (implemented by the knowledge module)."""

    async def index_snapshot(
        self, scope: TenantScope, source_id: UUID, snapshot_id: UUID, *, force: bool = False
    ) -> int: ...


@dataclass(frozen=True)
class SourceDependencies:
    database: Database
    fetcher: SafeFetcher
    robots: RobotsCache
    politeness: Politeness
    reputation: ReputationModel
    queue: JobQueue
    audit: AuditService
    clock: Clock
    egress: EgressSettings
    security: SecuritySettings
    metrics: Metrics
    limiter: RateLimiter
    parser: SandboxedParser | None = None
    """Sandboxed parser for binary web content (PDF); without it only text types are fetched."""
    indexer: SnapshotIndexer | None = None


def extract_text_content(result: FetchResult) -> ExtractedContent:
    media = result.media_type
    if media in {
        "text/html",
        "application/xhtml+xml",
        "application/xml",
        "text/xml",
        "application/rss+xml",
        "application/atom+xml",
    }:
        page = extract_html(result.text(), base_url=result.url, max_chars=MAX_TEXT_CHARS)
        return ExtractedContent(
            title=page.title,
            text=page.text,
            details={
                "description": page.description,
                "canonical_url": page.canonical_url,
                "links": [{"url": link.url, "text": link.text} for link in page.links[:50]],
                "hidden_elements": page.hidden_elements,
            },
            hidden_text=page.hidden_text,
            invisible=page.invisible_characters,
            author=page.author,
            publisher=page.publisher,
            published_at=page.published_at,
            language=page.language,
        )
    raw = result.text()
    if media in {"application/json", "application/ld+json"}:
        # Pretty-print for readability; deeply nested JSON raises RecursionError - keep it raw.
        with contextlib.suppress(ValueError, RecursionError):
            raw = json.dumps(json.loads(raw), indent=2, ensure_ascii=False)[:MAX_TEXT_CHARS]
    clean = sanitize_text(raw, max_chars=MAX_TEXT_CHARS)
    return ExtractedContent(
        title=None, text=clean.text, details={}, invisible=clean.suspicious_invisible
    )


class SourceService:
    def __init__(self, deps: SourceDependencies) -> None:
        self._d = deps
        self.accepted_types = TEXT_TYPES | DOCUMENT_TYPES if deps.parser is not None else TEXT_TYPES

    # ------------------------------------------------------------------- policies
    async def domain_policies(self, scope: TenantScope) -> list[DomainPolicy]:
        async with self._d.database.tenant(scope, read_only=True) as session:
            return list(
                (
                    await session.execute(
                        select(DomainPolicy).where(
                            DomainPolicy.organization_id == scope.organization_id
                        )
                    )
                )
                .scalars()
                .all()
            )

    @staticmethod
    def _policy_for(host: str, policies: list[DomainPolicy]) -> DomainPolicy | None:
        matches = [p for p in policies if domain_matches(host, p.domain)]
        return max(matches, key=lambda p: len(p.domain)) if matches else None

    def _gate(
        self, policies: list[DomainPolicy], approved: frozenset[str] = frozenset()
    ) -> Callable[[SafeURL], Awaitable[None]]:
        async def gate(url: SafeURL) -> None:
            policy = self._policy_for(url.host, policies)
            if policy is not None and policy.policy == "block":
                raise FetchError("domain_blocked", url.host)
            if (
                policy is not None
                and policy.policy == "require_approval"
                and not any(domain_matches(url.host, domain) for domain in approved)
            ):
                raise FetchError("domain_requires_approval", url.host)
            delay = None
            if self._d.egress.respect_robots_txt:
                decision = await self._d.robots.check(url)
                if not decision.allowed:
                    code = (
                        "robots_unreachable"
                        if decision.reason == "unreachable"
                        else "robots_disallowed"
                    )
                    raise FetchError(code, str(url))
                delay = decision.crawl_delay_s
            await self._d.politeness.wait(url.host, delay)

        return gate

    # -------------------------------------------------------------------- collect
    @staticmethod
    async def _upsert_source(
        session: AsyncSession,
        scope: TenantScope,
        url: SafeURL,
        *,
        discovered_via: Discovery,
        job_id: UUID | None,
        search_query: str | None,
    ) -> UUID:
        if scope.project_id is None:
            msg = "sources are always registered inside a project scope"
            raise ValueError(msg)
        row = (
            await session.execute(
                text(
                    "INSERT INTO sources (id, organization_id, project_id, url, url_hash, domain, "
                    "discovered_via, discovered_by_job_id, search_query, created_by, status, "
                    "reputation, trust_tier, injection_level, injection_score, fetch_count, "
                    "created_at, updated_at) VALUES (:id, :org, :project, :url, :hash, "
                    ":domain, :via, :job, :query, :by, 'pending', 0.5, 'unknown', 'none', 0, 0, "
                    "now(), now()) ON CONFLICT (organization_id, project_id, url_hash) "
                    "DO UPDATE SET updated_at = now() RETURNING id"
                ),
                {
                    "id": uuid7(),
                    "org": scope.organization_id,
                    "project": scope.project_id,
                    "url": str(url),
                    "hash": sha256(str(url)),
                    "domain": url.host,
                    "via": discovered_via,
                    "job": job_id,
                    "query": search_query[:500] if search_query else None,
                    "by": scope.actor.user_id,
                },
            )
        ).scalar_one()
        return UUID(str(row))

    async def _mark(
        self, scope: TenantScope, source_id: UUID, status: str, code: str | None
    ) -> None:
        async with self._d.database.tenant(scope) as session:
            await session.execute(
                text(
                    "UPDATE sources SET status = :status, last_error_code = :code, updated_at = now(), "
                    "last_fetched_at = now(), fetch_count = fetch_count + 1 WHERE id = :id"
                ),
                {"status": status, "code": code, "id": source_id},
            )

    async def collect(
        self,
        scope: TenantScope,
        raw_url: str,
        *,
        discovered_via: Discovery = "manual",
        job_id: UUID | None = None,
        search_query: str | None = None,
        policies: list[DomainPolicy] | None = None,
        accept: frozenset[str] | None = None,
        approved_domains: frozenset[str] = frozenset(),
    ) -> CollectOutcome:
        """``approved_domains``: ``require_approval`` domains a human approved for this job."""
        url = parse_url(raw_url, allowed_ports=self._d.egress.allowed_ports)
        async with self._d.database.tenant(scope) as session:
            source_id = await self._upsert_source(
                session,
                scope,
                url,
                discovered_via=discovered_via,
                job_id=job_id,
                search_query=search_query,
            )
        if policies is None:
            policies = await self.domain_policies(scope)
        try:
            result = await self._d.fetcher.fetch(
                str(url),
                accept=accept or self.accepted_types,
                gate=self._gate(policies, approved_domains),
            )
            content = await self._extract(result)
        except FetchError as exc:
            status: Literal["blocked", "failed", "needs_approval"] = (
                "needs_approval"
                if exc.code == "domain_requires_approval"
                else "blocked"
                if exc.code in {"blocked", "domain_blocked", "robots_disallowed"}
                else "failed"
            )
            await self._mark(
                scope, source_id, "blocked" if status != "failed" else "failed", exc.code
            )
            log.info("source.fetch_failed", code=exc.code, domain=url.host)
            return CollectOutcome(source_id, status, error_code=exc.code)
        except HTMLTooComplex:
            await self._mark(scope, source_id, "failed", "page_too_complex")
            return CollectOutcome(source_id, "failed", error_code="page_too_complex")

        verdict = assess(
            content.text,
            hidden_text=content.hidden_text,
            invisible_characters=content.invisible,
            flag_threshold=self._d.security.injection_flag_threshold,
            block_threshold=self._d.security.injection_block_threshold,
        )
        self._d.metrics.injection_detections.labels(verdict.level.value).inc()
        policy = self._policy_for(url.host, policies)
        reputation = self._d.reputation.lookup(
            url.host, override=policy.reputation_override if policy is not None else None
        )
        snapshot_id, inserted = await self._store_snapshot(
            scope, source_id, result, content, verdict
        )
        async with self._d.database.tenant(scope) as session:
            await session.execute(
                text(
                    "UPDATE sources SET status = 'fetched', last_error_code = NULL, title = :title, "
                    "author = :author, publisher = :publisher, published_at = :published, "
                    "language = :language, reputation = :reputation, trust_tier = :tier, "
                    "injection_level = :level, injection_score = :score, last_fetched_at = now(), "
                    "fetch_count = fetch_count + 1, updated_at = now() WHERE id = :id"
                ),
                {
                    "title": clean_line(content.title, 300),
                    "author": clean_line(content.author, 200),
                    "publisher": clean_line(content.publisher, 200),
                    "published": content.published_at,
                    "language": clean_line(content.language, 16),
                    "reputation": reputation.score,
                    "tier": reputation.tier,
                    "level": verdict.level.value,
                    "score": verdict.score,
                    "id": source_id,
                },
            )
        if self._d.indexer is not None:
            # Idempotent: an unchanged page whose snapshot is already indexed costs one query.
            await self._d.indexer.index_snapshot(scope, source_id, snapshot_id)
        return CollectOutcome(
            source_id,
            "fetched",
            snapshot_id,
            inserted,
            None,
            verdict.level.value,
            content.title,
            result.media_type,
        )

    async def _extract(self, result: FetchResult) -> ExtractedContent:
        if result.media_type in TEXT_TYPES:
            return extract_text_content(result)
        if result.media_type == "application/pdf" and self._d.parser is not None:
            # Never parsed in this process: the sandbox does it, and its output is re-sanitised
            # and assessed like any other page.
            try:
                parsed = await self._d.parser.parse(result.content, "pdf")
            except ParseError as exc:
                raise FetchError("unparseable", exc.code) from None
            return ExtractedContent(
                title=clean_line(parsed.title, 300),
                text=sanitize_text(parsed.text, max_chars=MAX_TEXT_CHARS).text,
                details={
                    "pages": parsed.page_count,
                    "active_content": parsed.metadata.get("active_content", []),
                },
                hidden_text=parsed.hidden_text,
                invisible=parsed.invisible_characters,
                author=clean_line(parsed.author, 200),
            )
        raise FetchError("content_type", result.media_type)

    async def _store_snapshot(
        self,
        scope: TenantScope,
        source_id: UUID,
        result: FetchResult,
        content: ExtractedContent,
        verdict: Any,
    ) -> tuple[UUID, bool]:
        signals = [
            {"category": s.category, "pattern": s.pattern, "excerpt": s.excerpt[:120]}
            for s in verdict.signals
        ]
        details = {
            **content.details,
            "headers": result.headers,
            "redirects": result.redirects,
            "hidden_text_excerpt": content.hidden_text[:500] or None,
        }
        async with self._d.database.tenant(scope) as session:
            row = (
                await session.execute(
                    text(
                        "INSERT INTO source_snapshots (id, organization_id, source_id, fetched_at, "
                        "last_seen_at, final_url, http_status, media_type, content_hash, byte_size, "
                        "server_ip, title, text, details, injection_score, injection_level, "
                        "injection_signals, created_at) VALUES (:id, :org, :source, "
                        ":fetched, :fetched, :url, :status, :media, :hash, :size, :ip, :title, :text, "
                        "CAST(:details AS jsonb), :score, :level, CAST(:signals AS jsonb), now()) "
                        "ON CONFLICT (source_id, content_hash) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at "
                        "RETURNING id, (xmax = 0) AS inserted"
                    ),
                    {
                        "id": uuid7(),
                        "org": scope.organization_id,
                        "source": source_id,
                        "fetched": result.fetched_at,
                        "url": result.url,
                        "status": result.status,
                        "media": result.media_type,
                        "hash": sha256(content.text),
                        "size": len(result.content),
                        "ip": result.server_ip,
                        "title": clean_line(content.title, 300),
                        "text": content.text,
                        "details": json.dumps(details, default=str),
                        "score": verdict.score,
                        "level": verdict.level.value,
                        "signals": json.dumps(signals),
                    },
                )
            ).one()
        return UUID(str(row.id)), bool(row.inserted)

    # ------------------------------------------------------------------ API use cases
    async def add(self, access: ProjectAccess, url: str, client: ClientInfo) -> SourceResponse:
        access.require(Permission.SOURCES_MANAGE)
        safe = parse_url(url, allowed_ports=self._d.egress.allowed_ports)
        # Every addition causes outbound traffic: cap it per organisation (anti-abuse; the
        # per-domain politeness limit alone would not stop fan-out across many domains).
        decision = await self._d.limiter.hit(
            POLICIES["sources.add.org"], str(access.org.organization_id)
        )
        if not decision.allowed:
            raise RateLimited(decision.retry_after_s)
        async with self._d.database.tenant(access.scope) as session:
            source_id = await self._upsert_source(
                session, access.scope, safe, discovered_via="manual", job_id=None, search_query=None
            )
            await self._d.queue.enqueue(
                session,
                JobSpec(
                    task=FETCH_TASK,
                    payload={
                        "organization_id": str(access.org.organization_id),
                        "project_id": str(access.project_id),
                        "url": str(safe),
                        "user_id": str(access.org.principal.user_id)
                        if access.org.principal.user_id
                        else None,
                    },
                    queue="default",
                    organization_id=access.org.organization_id,
                    max_attempts=3,
                    timeout_s=120,
                    dedup_key=f"source:{source_id}",
                ),
            )
            await self._d.audit.record(
                session,
                AuditEvent(
                    action="source.added",
                    category=AuditCategory.DATA_ACCESS,
                    actor=access.scope.actor,
                    organization_id=access.org.organization_id,
                    target_type="source",
                    target_id=str(source_id),
                    client=client,
                    details={"domain": safe.host},
                ),
            )
            source = await session.get(Source, source_id)
            if source is None:
                raise NotFound
            return SourceResponse.model_validate(source)

    async def list_sources(self, access: ProjectAccess, page: PageQuery) -> Page[SourceResponse]:
        access.require(Permission.SOURCES_READ)
        cursor = page.decoded()
        stmt = select(Source).where(
            Source.organization_id == access.org.organization_id,
            Source.project_id == access.project_id,
        )
        if cursor is not None:
            stmt = stmt.where(
                (Source.created_at < cursor.created_at)
                | ((Source.created_at == cursor.created_at) & (Source.id < cursor.id))
            )
        stmt = stmt.order_by(Source.created_at.desc(), Source.id.desc()).limit(page.limit + 1)
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            rows = list((await session.execute(stmt)).scalars().all())
        next_cursor = None
        if len(rows) > page.limit:
            rows = rows[: page.limit]
            next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id)
        return Page[SourceResponse](
            items=[SourceResponse.model_validate(r) for r in rows], next_cursor=next_cursor
        )

    async def get(self, access: ProjectAccess, source_id: UUID) -> SourceDetail:
        access.require(Permission.SOURCES_READ)
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            source = (
                await session.execute(
                    select(Source).where(
                        Source.organization_id == access.org.organization_id,
                        Source.project_id == access.project_id,
                        Source.id == source_id,
                    )
                )
            ).scalar_one_or_none()
            if source is None:
                raise NotFound
            snapshot = (
                await session.execute(
                    select(SourceSnapshot)
                    .where(SourceSnapshot.source_id == source_id)
                    .order_by(SourceSnapshot.last_seen_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
        detail = SourceDetail.model_validate(source)
        if snapshot is not None:
            detail = detail.model_copy(
                update={
                    "latest_snapshot": SnapshotDetail(
                        **SnapshotSummary.model_validate(snapshot).model_dump(),
                        server_ip=snapshot.server_ip,
                        text_excerpt=snapshot.text[:4000],
                        injection_signals=list(snapshot.injection_signals or []),
                        details={k: v for k, v in (snapshot.details or {}).items() if k != "links"},
                    )
                }
            )
        return detail

    async def snapshots(self, access: ProjectAccess, source_id: UUID) -> list[SnapshotSummary]:
        access.require(Permission.SOURCES_READ)
        async with self._d.database.tenant(access.scope, read_only=True) as session:
            exists = (
                await session.execute(
                    select(Source.id).where(
                        Source.project_id == access.project_id, Source.id == source_id
                    )
                )
            ).scalar_one_or_none()
            if exists is None:
                raise NotFound
            rows = (
                (
                    await session.execute(
                        select(SourceSnapshot)
                        .where(SourceSnapshot.source_id == source_id)
                        .order_by(SourceSnapshot.fetched_at.desc())
                        .limit(100)
                    )
                )
                .scalars()
                .all()
            )
        return [SnapshotSummary.model_validate(row) for row in rows]

    # ------------------------------------------------------------ domain policies
    async def list_policies(self, access: OrgAccess) -> list[DomainPolicyResponse]:
        access.require(Permission.SOURCES_READ)
        return [
            DomainPolicyResponse.model_validate(p) for p in await self.domain_policies(access.scope)
        ]

    async def set_policy(
        self, access: OrgAccess, domain: str, request: DomainPolicyRequest, client: ClientInfo
    ) -> DomainPolicyResponse:
        access.require(Permission.SOURCES_MANAGE)
        async with self._d.database.tenant(access.scope) as session:
            policy = (
                await session.execute(
                    select(DomainPolicy).where(
                        DomainPolicy.organization_id == access.organization_id,
                        DomainPolicy.domain == domain,
                    )
                )
            ).scalar_one_or_none()
            if policy is None:
                policy = DomainPolicy(
                    organization_id=access.organization_id,
                    domain=domain,
                    policy=request.policy,
                    created_by=access.principal.user_id,
                )
                session.add(policy)
            policy.policy = request.policy
            policy.reputation_override = request.reputation_override
            policy.note = request.note
            await session.flush()
            await self._d.audit.record(
                session,
                AuditEvent(
                    action="domain_policy.set",
                    category=AuditCategory.CONFIGURATION,
                    actor=access.scope.actor,
                    organization_id=access.organization_id,
                    target_type="domain",
                    target_id=domain,
                    client=client,
                    details={
                        "policy": request.policy,
                        "reputation_override": request.reputation_override,
                    },
                ),
            )
            return DomainPolicyResponse.model_validate(policy)

    async def delete_policy(self, access: OrgAccess, domain: str, client: ClientInfo) -> None:
        access.require(Permission.SOURCES_MANAGE)
        async with self._d.database.tenant(access.scope) as session:
            result = await session.execute(
                delete(DomainPolicy).where(
                    DomainPolicy.organization_id == access.organization_id,
                    DomainPolicy.domain == domain,
                )
            )
            if result.rowcount == 0:  # type: ignore[attr-defined]
                raise NotFound
            await self._d.audit.record(
                session,
                AuditEvent(
                    action="domain_policy.deleted",
                    category=AuditCategory.CONFIGURATION,
                    actor=access.scope.actor,
                    organization_id=access.organization_id,
                    target_type="domain",
                    target_id=domain,
                    client=client,
                ),
            )
