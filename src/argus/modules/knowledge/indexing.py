"""Turning parsed text into searchable chunks - for uploaded documents and collected web pages.

Per parent (document or snapshot): chunk → decide whether the text may be embedded by the
configured provider (organisation data policy vs. the provider's locality) → embed in batches
*outside* any transaction → in one transaction, replace the parent's chunks and bump the
project's corpus version (which invalidates retrieval caches). Re-indexing is idempotent.

Each chunk carries the stricter of its own injection assessment and its parent's: a document that
hid instructions somewhere is not trusted anywhere.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final
from uuid import UUID

from sqlalchemy import delete, exists, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.classification import Classification
from argus.core.clock import Clock
from argus.core.config import RetrievalSettings
from argus.core.crypto import sha256
from argus.core.ids import uuid7
from argus.core.logging import get_logger
from argus.core.scope import Actor, TenantScope
from argus.infrastructure.db import Database
from argus.infrastructure.observability.metrics import Metrics
from argus.modules.documents.models import Document
from argus.modules.knowledge.chunking import TextChunk, chunk_text
from argus.modules.knowledge.models import DocumentChunk
from argus.modules.llm.embeddings import Embedder
from argus.modules.llm.governance import may_send
from argus.modules.sources.models import Source, SourceSnapshot
from argus.modules.tenancy.corpus import bump_corpus_version
from argus.modules.tenancy.models import Organization
from argus.modules.tenancy.schemas import OrganizationSettings
from argus.security.injection import assess

log = get_logger(__name__)
_LEVELS: Final = ("none", "low", "medium", "high")
_LATIN: Final = re.compile(r"[A-Za-z]")
_LETTER: Final = re.compile(r"[^\W\d_]", re.UNICODE)


def fts_config_for(language: str | None, text: str) -> str:
    """English stemming for English text; language-neutral tokenisation for everything else."""
    if language:
        return "english" if language.lower().startswith("en") else "simple"
    sample = text[:4000]
    letters = len(_LETTER.findall(sample))
    return "english" if letters and len(_LATIN.findall(sample)) / letters > 0.9 else "simple"


def stricter(*levels: str) -> str:
    return max(levels, key=lambda level: _LEVELS.index(level) if level in _LEVELS else 3)


def _parse_date(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)  # Python 3.11+ accepts the "Z" suffix
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


@dataclass(frozen=True)
class _Parent:
    project_id: UUID
    text: str
    title: str | None
    classification: Classification
    published_at: datetime | None
    injection_level: str
    language: str | None
    page_offsets: list[int] | None


class KnowledgeIndexer:
    def __init__(
        self,
        *,
        database: Database,
        embedder: Embedder,
        settings: RetrievalSettings,
        clock: Clock,
        metrics: Metrics,
    ) -> None:
        self._db = database
        self._embedder = embedder
        self._settings = settings
        self._clock = clock
        self._metrics = metrics

    # ------------------------------------------------------------------ documents
    async def index_document(self, organization_id: UUID, document_id: UUID) -> int:
        scope = TenantScope(organization_id, Actor.system())
        async with self._db.tenant(scope, read_only=True) as session:
            document = await session.get(Document, document_id)
            policy = await self._policy(session, organization_id)
        if document is None or document.text is None:
            return 0
        metadata = (document.details or {}).get("metadata") or {}
        offsets = metadata.get("page_offsets") if isinstance(metadata, dict) else None
        parent = _Parent(
            project_id=document.project_id,
            text=document.text,
            title=document.title or document.filename,
            classification=Classification(document.classification),
            published_at=_parse_date((document.details or {}).get("created_at")),
            injection_level=document.injection_level,
            language=document.language,
            page_offsets=[o for o in offsets if isinstance(o, int)]
            if isinstance(offsets, list)
            else None,
        )
        return await self._index(
            scope, parent, policy, owner={"origin": "document", "document_id": document_id}
        )

    # ------------------------------------------------------------------- web pages
    async def index_snapshot(
        self, scope: TenantScope, source_id: UUID, snapshot_id: UUID, *, force: bool = False
    ) -> int:
        """Index a source's current content; chunks of its older snapshots are replaced."""
        async with self._db.tenant(scope, read_only=True) as session:
            if (
                not force
                and (
                    await session.execute(
                        select(exists().where(DocumentChunk.snapshot_id == snapshot_id))
                    )
                ).scalar_one()
            ):
                return 0
            row = (
                await session.execute(
                    select(SourceSnapshot, Source)
                    .join(Source, Source.id == SourceSnapshot.source_id)
                    .where(SourceSnapshot.id == snapshot_id, Source.id == source_id)
                )
            ).one_or_none()
            policy = await self._policy(session, scope.organization_id)
        if row is None:
            return 0
        snapshot, source = row
        parent = _Parent(
            project_id=source.project_id,
            text=snapshot.text,
            title=snapshot.title or source.title or source.domain,
            classification=Classification.PUBLIC,  # collected from the open web
            published_at=source.published_at,
            injection_level=snapshot.injection_level,
            language=source.language,
            page_offsets=None,
        )
        return await self._index(
            scope,
            parent,
            policy,
            owner={"origin": "web", "source_id": source_id, "snapshot_id": snapshot_id},
        )

    # ---------------------------------------------------------------------- shared
    @staticmethod
    async def _policy(session: AsyncSession, organization_id: UUID) -> OrganizationSettings:
        raw = (
            await session.execute(
                select(Organization.settings).where(Organization.id == organization_id)
            )
        ).scalar_one_or_none()
        return OrganizationSettings.model_validate(raw or {})

    async def _embed(self, chunks: list[TextChunk]) -> list[list[float]]:
        return await self._embedder.embed([chunk.text for chunk in chunks], kind="document")

    async def _index(
        self,
        scope: TenantScope,
        parent: _Parent,
        settings: OrganizationSettings,
        *,
        owner: dict[str, Any],
    ) -> int:
        chunks = chunk_text(
            parent.text,
            target=self._settings.chunk_chars,
            overlap=self._settings.chunk_overlap_chars,
            page_offsets=parent.page_offsets,
        )
        embeddable = may_send(parent.classification, self._embedder.locality, settings.data_policy)
        vectors = await self._embed(chunks) if chunks and embeddable else None
        fts = fts_config_for(parent.language, parent.text)
        now = self._clock.now()
        rows = [
            {
                "id": uuid7(),
                "organization_id": scope.organization_id,
                "project_id": parent.project_id,
                "document_id": owner.get("document_id"),
                "source_id": owner.get("source_id"),
                "snapshot_id": owner.get("snapshot_id"),
                "origin": owner["origin"],
                "ordinal": chunk.ordinal,
                "text": chunk.text,
                "char_start": chunk.char_start,
                "char_end": chunk.char_end,
                "page_start": chunk.page_start,
                "page_end": chunk.page_end,
                "content_hash": sha256(chunk.text),
                "token_estimate": chunk.token_estimate,
                "title": parent.title[:300] if parent.title else None,
                "classification": int(parent.classification),
                "published_at": parent.published_at,
                "injection_level": stricter(assess(chunk.text).level.value, parent.injection_level),
                "fts_config": fts,
                "embedding": vectors[i] if vectors is not None else None,
                "embedding_model": self._embedder.model if vectors is not None else None,
                "created_at": now,
            }
            for i, chunk in enumerate(chunks)
        ]
        async with self._db.tenant(scope) as session:
            if owner["origin"] == "document":
                await session.execute(
                    delete(DocumentChunk).where(DocumentChunk.document_id == owner["document_id"])
                )
            else:
                await session.execute(
                    delete(DocumentChunk).where(DocumentChunk.source_id == owner["source_id"])
                )
            if rows:
                await session.execute(insert(DocumentChunk), rows)
            await bump_corpus_version(session, parent.project_id)
        self._metrics.chunks_indexed.labels(owner["origin"], str(vectors is not None).lower()).inc(
            len(rows)
        )
        if not embeddable and chunks:
            log.info(
                "knowledge.embedding_withheld",
                reason="classification above the provider's data-policy ceiling",
                provider=self._embedder.provider,
            )
        return len(rows)
