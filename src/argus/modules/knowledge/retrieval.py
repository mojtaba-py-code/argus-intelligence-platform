"""Hybrid retrieval with authorisation *inside* the query (ADR 0004).

``SearchScope`` is computed from the caller's access before anything is searched - organisation,
readable projects, classification ceiling, allowed origins, excluded injection levels - and becomes
the ``WHERE`` clause of both candidate searches; row-level security applies on top. The vector
search (HNSW, cosine) and the keyword search (GIN; any of the query's terms, English-stemmed and
language-neutral, ranked by cover density) run in **one** statement and are fused with Reciprocal Rank Fusion. The
language model never sees, and is never asked to filter, anything outside the scope.

Then: rerank (lexical by default; Voyage when configured and the data policy allows sending the
candidates), cap chunks per parent so one long document cannot crowd out the rest, and cache the
result - encrypted, keyed by the scope, the projects' corpus versions and the query.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
import unicodedata
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Final, Literal, Protocol
from uuid import UUID

from pgvector.sqlalchemy import Vector
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.classification import Classification
from argus.core.config import RetrievalSettings
from argus.core.crypto import CryptoError, Keyring
from argus.core.logging import get_logger
from argus.core.scope import Actor, TenantScope
from argus.infrastructure.db import Database
from argus.infrastructure.observability.metrics import Metrics
from argus.infrastructure.observability.tracing import set_attributes, span
from argus.infrastructure.redis import RedisKeys
from argus.modules.llm.embeddings import Embedder
from argus.modules.llm.governance import may_send
from argus.modules.llm.voyage import EMBEDDING_DIMENSIONS, ProviderError, ProviderUnavailable
from argus.modules.tenancy.schemas import DataPolicy

log = get_logger(__name__)
Mode = Literal["hybrid", "vector", "keyword"]
_TERM: Final = re.compile(r"\w+", re.UNICODE)
_QUERY_CLASSIFICATION: Final = Classification.INTERNAL  # a user's question is internal data


@dataclass(frozen=True)
class SearchScope:
    organization_id: UUID
    project_ids: tuple[UUID, ...]
    max_classification: Classification
    origins: frozenset[str] = frozenset({"document", "web"})
    exclude_injection: frozenset[str] = frozenset({"high"})
    published_after: datetime | None = None


@dataclass(frozen=True)
class Hit:
    chunk_id: UUID
    origin: str
    project_id: UUID
    document_id: UUID | None
    source_id: UUID | None
    snapshot_id: UUID | None
    ordinal: int
    text: str
    title: str | None
    url: str | None
    filename: str | None
    page_start: int | None
    page_end: int | None
    char_start: int
    char_end: int
    classification: int
    published_at: datetime | None
    injection_level: str
    score: float
    vector_rank: int | None = None
    keyword_rank: int | None = None

    @property
    def parent_key(self) -> str:
        return str(self.document_id or self.source_id)

    def to_json(self) -> dict[str, Any]:
        return {
            k: (str(v) if isinstance(v, UUID | datetime) else v) for k, v in asdict(self).items()
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Hit:
        uuids = ("chunk_id", "project_id", "document_id", "source_id", "snapshot_id")
        values: dict[str, Any] = {k: (UUID(v) if k in uuids and v else v) for k, v in data.items()}
        if values.get("published_at"):
            values["published_at"] = datetime.fromisoformat(values["published_at"])
        return cls(**values)


class Reranker(Protocol):
    name: str

    async def rerank(self, query: str, hits: list[Hit]) -> list[float]: ...


def query_terms(query: str) -> set[str]:
    return {
        term
        for term in _TERM.findall(unicodedata.normalize("NFKC", query).casefold())
        if len(term) > 1
    }


class LexicalReranker:
    """Deterministic and local: fused score blended with query-term coverage and phrase match."""

    name = "lexical"

    async def rerank(self, query: str, hits: list[Hit]) -> list[float]:
        terms = query_terms(query)
        phrase = " ".join(unicodedata.normalize("NFKC", query).casefold().split())
        top = max((hit.score for hit in hits), default=1.0) or 1.0
        scores = []
        for hit in hits:
            body = unicodedata.normalize("NFKC", hit.text).casefold()
            words = set(_TERM.findall(body))
            coverage = len(terms & words) / len(terms) if terms else 0.0
            bonus = 0.15 if len(phrase) > 3 and phrase in " ".join(body.split()) else 0.0
            scores.append(0.6 * (hit.score / top) + 0.4 * coverage + bonus)
        return scores


class VoyageReranker:
    name = "voyage"

    def __init__(self, client: Any, *, model: str = "rerank-2.5") -> None:
        self._client = client
        self._model = model

    async def rerank(self, query: str, hits: list[Hit]) -> list[float]:
        scores: list[float] = await self._client.rerank(
            query, [hit.text for hit in hits], model=self._model
        )
        return scores


def _filters(scope: SearchScope) -> tuple[str, dict[str, Any]]:
    clauses = [
        "c.organization_id = :org",
        "c.project_id = ANY(:projects)",
        "c.classification <= :ceiling",
        "c.origin = ANY(:origins)",
        "NOT (c.injection_level = ANY(:excluded))",
    ]
    params: dict[str, Any] = {
        "org": scope.organization_id,
        "projects": list(scope.project_ids),
        "ceiling": int(scope.max_classification),
        "origins": sorted(scope.origins),
        "excluded": sorted(scope.exclude_injection) or ["-"],
    }
    if scope.published_after is not None:
        clauses.append("c.published_at >= :after")
        params["after"] = scope.published_after
    return " AND ".join(clauses), params


class Retriever:
    def __init__(
        self,
        *,
        database: Database,
        embedder: Embedder,
        settings: RetrievalSettings,
        metrics: Metrics,
        keyring: Keyring,
        redis: Redis | None = None,
        keys: RedisKeys | None = None,
        reranker: Reranker | None = None,
    ) -> None:
        self._db = database
        self._embedder = embedder
        self._settings = settings
        self._metrics = metrics
        self._keyring = keyring
        self._redis = redis
        self._keys = keys
        self._reranker: Reranker | None = (
            reranker
            if reranker is not None
            else LexicalReranker()
            if settings.rerank != "none"
            else None
        )
        self._iterative_scan: bool | None = None
        self.reranker_client: Any = None
        """The HTTP client behind an external reranker, closed with the container."""

    # ------------------------------------------------------------------ public API
    async def search(
        self,
        scope: SearchScope,
        query: str,
        *,
        policy: DataPolicy,
        limit: int = 8,
        mode: Mode = "hybrid",
    ) -> list[Hit]:
        if not scope.project_ids or not query.strip():
            return []
        with span(
            "knowledge.retrieve",
            attributes={"argus.retrieval.mode": mode, "argus.retrieval.limit": limit},
        ) as current:
            hits, cache = await self._search(scope, query, policy=policy, limit=limit, mode=mode)
            set_attributes(current, {"argus.retrieval.results": len(hits), "argus.cache": cache})
        self._metrics.retrievals.labels(mode, cache).inc()
        self._metrics.retrieval_results.labels(mode).observe(len(hits))
        return hits

    async def _search(
        self, scope: SearchScope, query: str, *, policy: DataPolicy, limit: int, mode: Mode
    ) -> tuple[list[Hit], str]:
        started = time.perf_counter()
        tenant = TenantScope(scope.organization_id, Actor.system())
        async with self._db.tenant(tenant, read_only=True) as session:
            versions = await self._versions(session, scope)
            key = self._cache_key(scope, query, limit, mode, versions)
            cached = await self._cache_get(key)
            if cached is not None:
                return cached, "hit"
            vector = await self._query_vector(query, mode, policy)
            candidates = await self._candidates(session, scope, query, vector, mode, limit)
        hits = await self._rerank(query, candidates, policy)
        hits = self._cap_per_parent(hits, limit)
        await self._cache_put(key, hits)
        self._metrics.retrieval_latency.observe(time.perf_counter() - started)
        return hits, "miss"

    async def highest_classification(self, scope: SearchScope) -> Classification | None:
        """The most sensitive chunk this scope can return (``None`` when it is empty)."""
        where, params = _filters(scope)
        tenant = TenantScope(scope.organization_id, Actor.system())
        async with self._db.tenant(tenant, read_only=True) as session:
            value = (
                await session.execute(
                    text(f"SELECT max(c.classification) FROM document_chunks c WHERE {where}"),  # nosec B608
                    params,
                )
            ).scalar_one_or_none()
        return None if value is None else Classification(value)

    # ---------------------------------------------------------------- query vector
    async def _query_vector(self, query: str, mode: Mode, policy: DataPolicy) -> list[float] | None:
        if mode == "keyword":
            return None
        if not may_send(_QUERY_CLASSIFICATION, self._embedder.locality, policy):
            log.info("knowledge.query_embedding_withheld", provider=self._embedder.provider)
            return None
        try:
            [vector] = await self._embedder.embed([query[:2000]], kind="query")
        except (ProviderUnavailable, ProviderError) as exc:
            # Degrade to keyword search rather than failing the whole research step.
            log.warning("knowledge.query_embedding_failed", error=type(exc).__name__)
            return None
        return vector

    # ------------------------------------------------------------------ candidates
    async def _supports_iterative_scan(self, session: AsyncSession) -> bool:
        if self._iterative_scan is None:
            version = (
                await session.execute(
                    text("SELECT extversion FROM pg_extension WHERE extname = 'vector'")
                )
            ).scalar_one_or_none()
            parts = [int(p) for p in str(version or "0").split(".")[:2] if p.isdigit()]
            self._iterative_scan = tuple(parts) >= (0, 8)
        return self._iterative_scan

    async def _candidates(
        self,
        session: AsyncSession,
        scope: SearchScope,
        query: str,
        vector: list[float] | None,
        mode: Mode,
        limit: int,
    ) -> list[Hit]:
        where, params = _filters(scope)
        k = self._settings.candidates
        # Keyword candidates match ANY term (OR): as a candidate generator, recall matters more
        # than the all-terms precision of web-search syntax. They are ranked with ts_rank, not
        # cover density (ts_rank_cd): measured on 10 000 matches it is 14x cheaper, and term
        # proximity is what the fusion and the reranker add afterwards. At most
        # keyword_rank_limit matches are ranked. Terms are \w+ tokens only, so they cannot carry
        # tsquery operators.
        terms = " | ".join(sorted(query_terms(query))[:32])
        params.update(
            q=terms,
            k=k,
            rrf_k=self._settings.rrf_k,
            fetch=max(limit * 4, 20),
            kcap=self._settings.keyword_rank_limit,
        )
        ctes = ["query AS (SELECT to_tsquery('english', :q) || to_tsquery('simple', :q) AS tsq)"]
        branches = []
        binds = []
        if vector is not None and mode in ("hybrid", "vector"):
            if await self._supports_iterative_scan(session):
                await session.execute(
                    text("SELECT set_config('hnsw.iterative_scan', 'relaxed_order', true)")
                )
                ef_search = self._settings.hnsw_ef_search
            else:  # pgvector < 0.8 filters after the scan: over-fetch so filters cannot starve k
                ef_search = max(self._settings.hnsw_ef_search, k * 4)
            await session.execute(
                text("SELECT set_config('hnsw.ef_search', :ef, true)"),
                {"ef": str(min(ef_search, 1000))},
            )
            ctes.append(
                "vector_hits AS (SELECT c.id, row_number() OVER (ORDER BY c.embedding <=> :qvec) AS rank "  # nosec B608
                f"FROM document_chunks c WHERE {where} AND c.embedding_model = :model "
                "ORDER BY c.embedding <=> :qvec LIMIT :k)"
            )
            branches.append("SELECT id, rank, 'v' AS kind FROM vector_hits")
            params["model"] = self._embedder.model
            params["qvec"] = vector
            binds.append(bindparam("qvec", type_=Vector(EMBEDDING_DIMENSIONS)))
        if mode in ("hybrid", "keyword") and terms:
            ctes.append(
                "keyword_matches AS (SELECT c.id, c.tsv FROM document_chunks c, query "  # nosec B608
                f"WHERE {where} AND c.tsv @@ query.tsq LIMIT :kcap)"
            )
            ctes.append(
                "keyword_hits AS (SELECT m.id, row_number() OVER "
                "(ORDER BY ts_rank(m.tsv, query.tsq) DESC, m.id) AS rank "
                "FROM keyword_matches m, query "
                "ORDER BY ts_rank(m.tsv, query.tsq) DESC, m.id LIMIT :k)"
            )
            branches.append("SELECT id, rank, 'k' AS kind FROM keyword_hits")
        if not branches:
            return []
        ctes.append(
            "fused AS (SELECT id, sum(1.0 / (:rrf_k + rank)) AS score, "  # nosec B608
            "min(rank) FILTER (WHERE kind = 'v') AS vector_rank, "
            "min(rank) FILTER (WHERE kind = 'k') AS keyword_rank "
            f"FROM ({' UNION ALL '.join(branches)}) hits GROUP BY id)"
        )
        sql = (
            "WITH " + ", ".join(ctes) + " SELECT c.id, c.origin, c.project_id, c.document_id, "  # nosec B608
            "c.source_id, c.snapshot_id, c.ordinal, c.text, c.title, s.url, d.filename, "
            "c.page_start, c.page_end, c.char_start, c.char_end, c.classification, c.published_at, "
            "c.injection_level, f.score, f.vector_rank, f.keyword_rank "
            "FROM fused f JOIN document_chunks c ON c.id = f.id "
            "LEFT JOIN sources s ON s.id = c.source_id "
            "LEFT JOIN documents d ON d.id = c.document_id "
            "ORDER BY f.score DESC, c.id LIMIT :fetch"
        )
        statement = text(sql)
        if binds:
            statement = statement.bindparams(*binds)
        rows = (await session.execute(statement, params)).mappings().all()
        return [
            Hit(
                chunk_id=row["id"],
                origin=row["origin"],
                project_id=row["project_id"],
                document_id=row["document_id"],
                source_id=row["source_id"],
                snapshot_id=row["snapshot_id"],
                ordinal=row["ordinal"],
                text=row["text"],
                title=row["title"],
                url=row["url"],
                filename=row["filename"],
                page_start=row["page_start"],
                page_end=row["page_end"],
                char_start=row["char_start"],
                char_end=row["char_end"],
                classification=row["classification"],
                published_at=row["published_at"],
                injection_level=row["injection_level"],
                score=float(row["score"]),
                vector_rank=row["vector_rank"],
                keyword_rank=row["keyword_rank"],
            )
            for row in rows
        ]

    # ---------------------------------------------------------------- post-process
    async def _rerank(self, query: str, hits: list[Hit], policy: DataPolicy) -> list[Hit]:
        reranker = self._reranker
        if reranker is None or not hits:
            return hits
        if reranker.name != "lexical":
            sendable = may_send(_QUERY_CLASSIFICATION, "external", policy) and all(
                may_send(hit.classification, "external", policy) for hit in hits
            )
            if not sendable:
                reranker = LexicalReranker()  # never send text above the ceiling to rerank it
        try:
            scores = await reranker.rerank(query, hits)
        except (ProviderUnavailable, ProviderError) as exc:
            log.warning("knowledge.rerank_failed", error=type(exc).__name__)
            return hits
        ranked = sorted(
            zip(scores, hits, strict=True), key=lambda pair: (-pair[0], str(pair[1].chunk_id))
        )
        return [
            Hit(**{**asdict(hit), "score": round(score, 6) if math.isfinite(score) else 0.0})
            for score, hit in ranked
        ]

    def _cap_per_parent(self, hits: list[Hit], limit: int) -> list[Hit]:
        counts: dict[str, int] = {}
        kept: list[Hit] = []
        for hit in hits:
            if counts.get(hit.parent_key, 0) >= self._settings.per_document_cap:
                continue
            counts[hit.parent_key] = counts.get(hit.parent_key, 0) + 1
            kept.append(hit)
            if len(kept) == limit:
                break
        return kept

    # ----------------------------------------------------------------------- cache
    @staticmethod
    async def _versions(session: AsyncSession, scope: SearchScope) -> dict[str, int]:
        rows = await session.execute(
            text("SELECT id, corpus_version FROM projects WHERE id = ANY(:ids)"),
            {"ids": list(scope.project_ids)},
        )
        return {str(row.id): int(row.corpus_version) for row in rows}

    def _cache_key(
        self, scope: SearchScope, query: str, limit: int, mode: Mode, versions: dict[str, int]
    ) -> str | None:
        if self._redis is None or self._keys is None or self._settings.cache_ttl_s == 0:
            return None
        material = json.dumps(
            {
                "projects": sorted(versions.items()),
                "ceiling": int(scope.max_classification),
                "origins": sorted(scope.origins),
                "excluded": sorted(scope.exclude_injection),
                "after": scope.published_after.isoformat() if scope.published_after else None,
                "query": " ".join(query.split()),
                "limit": limit,
                "mode": mode,
                "model": self._embedder.model,
                "rerank": self._settings.rerank,
            },
            sort_keys=True,
        )
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
        return self._keys.org(scope.organization_id, "retrieval", digest)

    async def _cache_get(self, key: str | None) -> list[Hit] | None:
        if key is None or self._redis is None:
            return None
        try:
            blob = await self._redis.get(key)
            if blob is None:
                return None
            raw = blob.encode("latin-1") if isinstance(blob, str) else bytes(blob)
            payload = self._keyring.decrypt(raw, aad=key.encode("utf-8"))
            return [Hit.from_json(item) for item in json.loads(payload)]
        except (RedisError, CryptoError, ValueError, TypeError, KeyError):
            return None  # a cache is an optimisation: any problem means "miss"

    async def _cache_put(self, key: str | None, hits: list[Hit]) -> None:
        if key is None or self._redis is None:
            return
        payload = json.dumps([hit.to_json() for hit in hits]).encode("utf-8")
        try:
            # Chunk text is tenant data: encrypted in the cache like everywhere else at rest.
            await self._redis.set(
                key,
                self._keyring.encrypt(payload, aad=key.encode("utf-8")),
                ex=self._settings.cache_ttl_s,
            )
        except RedisError:
            log.warning("knowledge.cache_write_failed")
