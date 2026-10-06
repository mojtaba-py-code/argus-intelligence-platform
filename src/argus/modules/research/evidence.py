"""What a job's findings rest on: findings, their citations, the cited chunks and provenance.

Loaded inside the job's tenant scope (RLS) by the verification, contradiction and report stages.
Everything here is *derived from untrusted content* - statements were written by a model that
read web pages and documents, quotes come from those pages - so prompts receive it only as
nonce-delimited untrusted data, and renderers escape it.

Provenance follows the specification (source id, URL, type, retrieval and publication time,
content hash, document id, author, publisher, extraction method and a reliability score), so a
report can show, for every statement, where it came from and how it was obtained.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from argus.modules.documents.models import Document
from argus.modules.knowledge.models import DocumentChunk
from argus.modules.knowledge.retrieval import query_terms
from argus.modules.research.models import ResearchCitation, ResearchFinding
from argus.modules.sources.models import Source, SourceSnapshot

CHUNK_EXCERPT_CHARS: Final = 1500
_NUMBER: Final = re.compile(r"(?<![\w.])[-+]?\d[\d,]*(?:\.\d+)?")
_EXTRACTION: Final = {
    "text/html": "html-extraction",
    "application/xhtml+xml": "html-extraction",
    "application/pdf": "pdf-sandboxed-parser",
    "application/json": "json-text",
    "application/ld+json": "json-text",
    "text/plain": "plain-text",
    "text/markdown": "plain-text",
}


_STOPWORDS_TEXT: Final = (
    "a an and are as at be been but by can could did do does for from had has have he her his "
    "how i if in into is it its may might more most of on or our over she should so such than "
    "that the their them then there these they this those to under up was we were what when "
    "where which while who whom why will with would you your about after also among before "
    "between both during each other only same very"
)
_NEGATIONS_TEXT: Final = (
    "not no never none neither nor without cannot isnt arent wasnt werent doesnt dont didnt "
    "hasnt havent hadnt wont wouldnt cant couldnt shouldnt"
)
STOPWORDS: Final = frozenset(_STOPWORDS_TEXT.split())
_NEGATIONS: Final = frozenset(_NEGATIONS_TEXT.split())
_APOSTROPHES: Final = "'" + chr(0x2019)


def content_terms(text: str) -> set[str]:
    """Words that carry meaning (query terms minus stop words and bare numbers)."""
    return {
        term
        for term in query_terms(text)
        if term not in STOPWORDS and not term.replace(".", "").isdigit()
    }


_WORD: Final = re.compile(rf"[^\W\d_]+(?:[{_APOSTROPHES}][^\W\d_]+)?")


def negated(text: str) -> bool:
    """Whether a statement is phrased negatively ("did not grow", "no vendor ...")."""
    words = {
        word.translate({ord(mark): None for mark in _APOSTROPHES})
        for word in _WORD.findall(unicodedata.normalize("NFKC", text).casefold())
    }
    return bool(words & _NEGATIONS)


def numbers(text: str) -> set[str]:
    """Numeric tokens, normalised (``1,200`` = ``1200``, ``40.0`` = ``40``): figures in a claim
    must appear in its evidence."""
    found: set[str] = set()
    for match in _NUMBER.findall(unicodedata.normalize("NFKC", text)):
        value = match.replace(",", "").lstrip("+")
        if "." in value:
            value = value.rstrip("0").rstrip(".")
        found.add(value)
    return found


@dataclass(frozen=True)
class SourceRecord:
    key: str
    """``S1``, ``S2``... in order of first citation: stable within one report."""
    origin: str
    source_id: UUID | None
    document_id: UUID | None
    url: str | None
    title: str | None
    filename: str | None
    source_type: str
    media_type: str | None
    retrieved_at: datetime | None
    published_at: datetime | None
    content_hash: str | None
    author: str | None
    publisher: str | None
    extraction_method: str
    reputation: float | None
    trust_tier: str | None
    classification: int

    @property
    def parent(self) -> UUID | None:
        return self.source_id or self.document_id

    @property
    def label(self) -> str:
        return self.title or self.url or "untitled source"


@dataclass(frozen=True)
class CitationRecord:
    ref: str
    quote: str
    verified: bool
    chunk_id: UUID
    chunk_text: str
    classification: int
    injection_level: str
    """Prompt-injection risk of the cited chunk (none, low, medium, high)."""
    source: SourceRecord


@dataclass(frozen=True)
class FindingRecord:
    id: UUID
    ref: str
    """``F1``, ``F2``... in report order."""
    question_id: str
    ordinal: int
    statement: str
    kind: str
    confidence: float
    verified: bool
    support: str
    evidence_classification: int
    agent_run_id: UUID | None
    citations: tuple[CitationRecord, ...]

    @property
    def classification(self) -> int:
        return max([self.evidence_classification, *(c.classification for c in self.citations)])

    @property
    def parents(self) -> frozenset[UUID]:
        return frozenset(p for c in self.citations if (p := c.source.parent) is not None)

    @property
    def evidence_text(self) -> str:
        return "\n".join(c.chunk_text for c in self.citations)

    @property
    def newest_publication(self) -> datetime | None:
        dates = [c.source.published_at for c in self.citations if c.source.published_at]
        return max(dates) if dates else None

    @property
    def best_reputation(self) -> float | None:
        scores = [c.source.reputation for c in self.citations if c.source.reputation is not None]
        return max(scores) if scores else None


@dataclass(frozen=True)
class JobEvidence:
    findings: tuple[FindingRecord, ...]
    sources: tuple[SourceRecord, ...]

    def by_ref(self) -> dict[str, FindingRecord]:
        return {finding.ref: finding for finding in self.findings}

    def by_id(self) -> dict[UUID, FindingRecord]:
        return {finding.id: finding for finding in self.findings}


def _source(key: str, row: Any) -> SourceRecord:
    if row.origin == "web":
        media = row.snapshot_media_type
        return SourceRecord(
            key=key,
            origin="web",
            source_id=row.source_id,
            document_id=None,
            url=row.snapshot_final_url or row.source_url,
            title=row.source_title,
            filename=None,
            source_type="pdf" if media == "application/pdf" else "web page",
            media_type=media,
            retrieved_at=row.snapshot_fetched_at,
            published_at=row.source_published_at,
            content_hash=row.snapshot_content_hash.hex() if row.snapshot_content_hash else None,
            author=row.source_author,
            publisher=row.source_publisher,
            extraction_method=_EXTRACTION.get(media or "", "text-extraction"),
            reputation=row.source_reputation,
            trust_tier=row.source_trust_tier,
            classification=row.chunk_classification,
        )
    return SourceRecord(
        key=key,
        origin="document",
        source_id=None,
        document_id=row.document_id,
        url=None,
        title=row.document_title or row.document_filename,
        filename=row.document_filename,
        source_type=f"uploaded {row.document_kind}" if row.document_kind else "uploaded document",
        media_type=row.document_media_type,
        retrieved_at=row.document_created_at,
        published_at=None,
        content_hash=row.document_sha256.hex() if row.document_sha256 else None,
        author=row.document_author,
        publisher=None,
        extraction_method=f"sandboxed-parser:{row.document_kind or 'unknown'}",
        reputation=None,
        trust_tier="internal",
        classification=row.chunk_classification,
    )


async def load_job_evidence(
    session: AsyncSession, organization_id: UUID, job_id: UUID
) -> JobEvidence:
    findings = (
        (
            await session.execute(
                select(ResearchFinding)
                .where(
                    ResearchFinding.organization_id == organization_id,
                    ResearchFinding.job_id == job_id,
                )
                .order_by(
                    func.length(ResearchFinding.question_id),
                    ResearchFinding.question_id,
                    ResearchFinding.ordinal,
                )
            )
        )
        .scalars()
        .all()
    )
    rows: dict[UUID, list[Any]] = {finding.id: [] for finding in findings}
    if findings:
        result = await session.execute(
            select(
                ResearchCitation.finding_id,
                ResearchCitation.ref,
                ResearchCitation.quote,
                ResearchCitation.verified,
                ResearchCitation.chunk_id,
                DocumentChunk.text.label("chunk_text"),
                DocumentChunk.classification.label("chunk_classification"),
                DocumentChunk.injection_level.label("chunk_injection_level"),
                DocumentChunk.origin,
                DocumentChunk.source_id,
                DocumentChunk.document_id,
                Source.url.label("source_url"),
                Source.title.label("source_title"),
                Source.author.label("source_author"),
                Source.publisher.label("source_publisher"),
                Source.published_at.label("source_published_at"),
                Source.reputation.label("source_reputation"),
                Source.trust_tier.label("source_trust_tier"),
                SourceSnapshot.fetched_at.label("snapshot_fetched_at"),
                SourceSnapshot.content_hash.label("snapshot_content_hash"),
                SourceSnapshot.media_type.label("snapshot_media_type"),
                SourceSnapshot.final_url.label("snapshot_final_url"),
                Document.filename.label("document_filename"),
                Document.title.label("document_title"),
                Document.author.label("document_author"),
                Document.kind.label("document_kind"),
                Document.media_type.label("document_media_type"),
                Document.sha256.label("document_sha256"),
                Document.created_at.label("document_created_at"),
            )
            .join(DocumentChunk, DocumentChunk.id == ResearchCitation.chunk_id)
            .outerjoin(Source, Source.id == DocumentChunk.source_id)
            .outerjoin(SourceSnapshot, SourceSnapshot.id == DocumentChunk.snapshot_id)
            .outerjoin(Document, Document.id == DocumentChunk.document_id)
            .where(
                ResearchCitation.organization_id == organization_id,
                ResearchCitation.finding_id.in_(list(rows)),
            )
            .order_by(
                ResearchCitation.finding_id,
                func.length(ResearchCitation.ref),
                ResearchCitation.ref,
            )
        )
        for row in result:
            rows[row.finding_id].append(row)

    sources: dict[UUID, SourceRecord] = {}
    records: list[FindingRecord] = []
    for index, finding in enumerate(findings, start=1):
        citations: list[CitationRecord] = []
        for row in rows[finding.id]:
            parent = row.source_id or row.document_id
            source = sources.get(parent)
            if source is None:
                source = sources[parent] = _source(f"S{len(sources) + 1}", row)
            citations.append(
                CitationRecord(
                    ref=row.ref,
                    quote=row.quote,
                    verified=row.verified,
                    chunk_id=row.chunk_id,
                    chunk_text=row.chunk_text[:CHUNK_EXCERPT_CHARS],
                    classification=row.chunk_classification,
                    injection_level=row.chunk_injection_level,
                    source=source,
                )
            )
        records.append(
            FindingRecord(
                id=finding.id,
                ref=f"F{index}",
                question_id=finding.question_id,
                ordinal=finding.ordinal,
                statement=finding.statement,
                kind=finding.kind,
                confidence=finding.confidence,
                verified=finding.verified,
                support=finding.support,
                evidence_classification=finding.evidence_classification,
                agent_run_id=finding.agent_run_id,
                citations=tuple(citations),
            )
        )
    return JobEvidence(findings=tuple(records), sources=tuple(sources.values()))
