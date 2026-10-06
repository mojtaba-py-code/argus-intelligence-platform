"""Performance benchmarks with budgets (phase 21: "measure performance instead of guessing").

Skipped unless selected::

    pytest -m perf                         # 10 000 chunks
    ARGUS_TEST_PERF_CHUNKS=100000 pytest -m perf
    ARGUS_TEST_PERF_REPORT=bench.md pytest -m perf   # also write the results table

Everything runs in-process against real PostgreSQL (HNSW + GIN indexes, row-level security),
through the public API where a user would go through it. Budgets are deliberately loose for a
laptop: they catch order-of-magnitude regressions (a lost index, an N+1 query, a serialised
loop), not single-digit-percent noise. Production capacity is measured with
``scripts/load_test.py`` against a deployed environment.
"""

from __future__ import annotations

import asyncio
import os
import statistics
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import asyncpg
import pytest

from argus.core.config import Settings
from argus.infrastructure.queue import JobSpec
from argus.modules.llm.voyage import EMBEDDING_DIMENSIONS
from tests.support import (
    ApiHarness,
    DatabaseURLs,
    api_harness,
    bearer,
    create_org,
    create_project,
    register_and_login,
)

pytestmark = [pytest.mark.integration, pytest.mark.perf, pytest.mark.timeout(1800)]
CHUNKS = int(os.environ.get("ARGUS_TEST_PERF_CHUNKS", "10000"))
WORDS = [
    "market",
    "vendor",
    "support",
    "customer",
    "revenue",
    "growth",
    "pricing",
    "platform",
    "automation",
    "agent",
    "analytics",
    "compliance",
    "security",
    "contract",
    "renewal",
    "churn",
    "forecast",
    "quarter",
    "region",
    "partner",
    "product",
    "launch",
    "roadmap",
    "feature",
    "integration",
    "latency",
    "model",
    "evaluation",
    "benchmark",
    "retention",
    "acquisition",
    "funding",
    "investor",
    "competitor",
    "share",
    "segment",
    "enterprise",
    "startup",
    "regulation",
]
SEED = """
INSERT INTO document_chunks (id, organization_id, project_id, origin, document_id, ordinal, text,
    char_start, char_end, content_hash, token_estimate, classification, injection_level,
    fts_config, embedding, embedding_model)
SELECT gen_random_uuid(), $1, $2, 'document', $3, g,
       (SELECT string_agg(($4::text[])[1 + floor(random() * $5)::int], ' ')
          FROM generate_series(1, 60) WHERE g > 0),
       0, 400, sha256(g::text::bytea), 80, 1, 'none', 'english',
       (SELECT array_agg(random() - 0.5)::vector FROM generate_series(1, $6) WHERE g > 0),
       'hash-v1'
  FROM generate_series($7::int, $8::int) g
"""


@dataclass
class Measurement:
    name: str
    samples: list[float]

    @property
    def p50(self) -> float:
        return statistics.median(self.samples)

    @property
    def p95(self) -> float:
        ordered = sorted(self.samples)
        return ordered[max(0, round(0.95 * len(ordered)) - 1)]

    def row(self) -> str:
        return (
            f"| {self.name} | {len(self.samples)} | {self.p50 * 1000:.1f} | "
            f"{self.p95 * 1000:.1f} | {max(self.samples) * 1000:.1f} |"
        )


async def measure(
    name: str, call: Callable[[], Awaitable[None]], *, rounds: int, concurrency: int = 1
) -> Measurement:
    """Steady state: one unmeasured warm-up round first (pool connections opened, code paths
    and statement caches warm), then ``rounds`` rounds of ``concurrency`` parallel calls."""
    samples: list[float] = []

    async def one(record: bool) -> None:
        started = time.perf_counter()
        await call()
        if record:
            samples.append(time.perf_counter() - started)

    await asyncio.gather(*(one(False) for _ in range(concurrency)))
    for _ in range(rounds):
        await asyncio.gather(*(one(True) for _ in range(concurrency)))
    return Measurement(name, samples)


async def seed_chunks(database_urls: DatabaseURLs, org: str, project: str) -> None:
    """Bulk-load the corpus with the vector index dropped, then rebuild it from its own
    definition - one index build is far faster than maintaining HNSW row by row."""
    conn = await asyncpg.connect(database_urls.admin)
    try:
        hnsw = await conn.fetch(
            "SELECT indexname, indexdef FROM pg_indexes"
            " WHERE tablename = 'document_chunks' AND indexdef ILIKE '%USING hnsw%'"
        )
        for index in hnsw:
            await conn.execute(f'DROP INDEX "{index["indexname"]}"')
        document = await conn.fetchval(
            "INSERT INTO documents (id, organization_id, project_id, filename, kind, media_type,"
            " byte_size, sha256, storage_key, classification, status)"
            " VALUES (gen_random_uuid(), $1, $2, 'corpus.txt', 'text', 'text/plain', 1,"
            " sha256('perf-corpus'::bytea), 'perf/' || gen_random_uuid(), 1, 'ready')"
            " RETURNING id",
            UUID(org),
            UUID(project),
        )
        for start in range(1, CHUNKS + 1, 2_000):
            await conn.execute(
                SEED,
                UUID(org),
                UUID(project),
                document,
                WORDS,
                len(WORDS),
                EMBEDDING_DIMENSIONS,
                start,
                min(CHUNKS, start + 1_999),
            )
        for index in hnsw:
            await conn.execute(index["indexdef"])
        # As after any bulk load: vacuum and analyse now, or autovacuum starts on its own - in
        # the middle of the measurements, competing with them.
        await conn.execute("VACUUM (ANALYZE) document_chunks")
        await conn.execute("VACUUM (ANALYZE) documents")
    finally:
        await conn.close()


async def test_hot_paths_meet_their_budgets(
    db_settings: Settings, database_urls: DatabaseURLs, tmp_path: Path
) -> None:
    del tmp_path
    async with api_harness(db_settings) as h:
        results = await run_benchmarks(h, database_urls)
    table = "\n".join(
        [
            f"Benchmarks ({CHUNKS} chunks, in-process, milliseconds)",
            "",
            "| operation | samples | p50 | p95 | max |",
            "|---|---|---|---|---|",
            *(m.row() for m in results.measurements),
            "",
            f"queue throughput: {results.jobs_per_second:.0f} jobs/s (enqueue + claim + complete)",
        ]
    )
    if report := os.environ.get("ARGUS_TEST_PERF_REPORT"):
        Path(report).write_text(table + "\n", encoding="utf-8")
    # About three times what a 2026 laptop measures (docs/phases/phase-21-performance.md):
    # room for slower CI machines, tight enough to catch a lost index or a serialised loop.
    budgets = {
        "search hybrid": 0.25,
        "search keyword": 0.2,
        "search vector": 0.15,
        # Ten parallel requests share one event loop, so their tail follows the machine's
        # load more than any other measurement: three times the laptop's p95 (263 ms).
        "list research jobs x10": 0.8,
        "list sources x10": 0.8,
        "security summary": 0.4,
    }
    over = [
        f"{m.name}: p95 {m.p95 * 1000:.0f} ms > {budgets[m.name] * 1000:.0f} ms"
        for m in results.measurements
        if m.name in budgets and m.p95 > budgets[m.name]
    ]
    assert not over, "\n".join([*over, "", table])
    assert results.jobs_per_second >= 100, table


@dataclass
class Results:
    measurements: list[Measurement]
    jobs_per_second: float


async def run_benchmarks(h: ApiHarness, database_urls: DatabaseURLs) -> Results:
    _, tokens = await register_and_login(h)
    owner = tokens["access_token"]
    org = (await create_org(h, owner, "Bench Co"))["id"]
    project = (await create_project(h, owner, org))["id"]
    await seed_chunks(database_urls, org, project)
    base = f"/api/v1/orgs/{org}/projects/{project}"
    counter = iter(range(1_000_000))

    def search(mode: str) -> Callable[[], Awaitable[None]]:
        async def call() -> None:
            # A different query every time: nothing is served from a cache.
            query = f"{WORDS[next(counter) % len(WORDS)]} vendor pricing {next(counter)}"
            response = await h.client.post(
                f"{base}/search",
                json={"query": query, "mode": mode, "limit": 8},
                headers=bearer(owner),
            )
            assert response.status_code == 200, response.text

        return call

    def get(path: str) -> Callable[[], Awaitable[None]]:
        async def call() -> None:
            response = await h.client.get(path, headers=bearer(owner))
            assert response.status_code == 200, response.text

        return call

    measurements = [
        await measure("search hybrid", search("hybrid"), rounds=40),
        await measure("search keyword", search("keyword"), rounds=40),
        await measure("search vector", search("vector"), rounds=40),
        await measure(
            "list research jobs x10", get(f"{base}/research-jobs"), rounds=10, concurrency=10
        ),
        await measure("list sources x10", get(f"{base}/sources"), rounds=10, concurrency=10),
        await measure("security summary", get(f"/api/v1/orgs/{org}/security/summary"), rounds=10),
    ]
    return Results(measurements, await queue_throughput(h, org))


async def queue_throughput(h: ApiHarness, org: str, jobs: int = 500) -> float:
    queue = h.container.queue
    task = "bench.noop"  # claim/complete never look the task up: no handler needed
    started = time.perf_counter()
    async with h.container.database.session() as session:
        for _ in range(jobs):
            await queue.enqueue(
                session, JobSpec(task=task, queue="bench", organization_id=UUID(org))
            )
    done = 0
    while done < jobs:
        claimed = await queue.claim(worker_id="bench", queues=("bench",), limit=50, lease_s=60)
        if not claimed:
            break
        for job in claimed:
            await queue.complete(job, {})
        done += len(claimed)
    elapsed = time.perf_counter() - started
    assert done == jobs
    return jobs / elapsed
