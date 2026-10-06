# Phase 21 - Performance and scalability

## 1. Purpose
"Measure performance instead of guessing" (spec §59). This phase adds the measuring tools -
benchmarks with budgets, a query-plan check over every statement the platform issues, pool and
statement metrics, a load-test script - and then fixes what the measurements showed, keeping
every security property intact.

## 2. What was measured, and what changed

Benchmarks: `pytest -m perf` (10 000 chunks, in-process API, local PostgreSQL 16, Windows
laptop). Numbers are p50 / p95 in milliseconds.

| Operation | Before | After | Change |
|---|---|---|---|
| Hybrid search | 285 / 298 | 62 / 68 | keyword branch ranked with `ts_rank` instead of `ts_rank_cd`, bounded by `keyword_rank_limit` |
| Keyword search | 277 / 286 | 54 / 61 | same |
| Vector search (HNSW) | 31 / 32 | 27 / 33 | unchanged (already index-served) |
| 10 concurrent list requests | 258 / 337 | 216 / 263 | one transaction for organisation + project authorisation; no SQL redaction for unrecorded spans (the *before* run also had no warm-up round, which accounts for part of the p95) |
| Security summary | 52 / 153 | 31 / 74 | same request-path savings (same warm-up caveat) |
| Queue (enqueue + claim + complete) | 189 jobs/s | 213 jobs/s | - |

Per request (profiled): 13 → 11 statements and one transaction fewer for every
project-scoped call; the database-span hook went from ~1.4 ms to ~0.4 ms per request when
tracing is off or the trace is not sampled.

### Measured and rejected
* **Folding `SET TRANSACTION READ ONLY` into the `set_config` statement** would save one round
  trip per read-only transaction. A probe showed that `set_config('transaction_read_only',
  'on', true)` does *not* make the transaction read-only in PostgreSQL 16 - an INSERT still
  succeeds. The separate statement stays: read-only sessions are a safety property, not an
  optimisation target.
* **Ranking every keyword match with cover density.** `ts_rank_cd` rewards term proximity, but
  it cost 180 ms for 9 600 matches against 13 ms for `ts_rank`; proximity is what fusion with
  the vector branch and the reranker contribute afterwards. Retrieval-quality tests and the
  evaluation baseline are unchanged.

## 3. The tools
* **`tests/perf/test_benchmarks.py`** (`pytest -m perf`, skipped otherwise): seeds a corpus with
  the vector index rebuilt once and the table vacuumed and analysed (as after any bulk load -
  otherwise autovacuum starts in the middle of the measurements), measures search in three modes,
  concurrent list endpoints, the security summary and queue throughput after a warm-up round,
  and fails when a p95 exceeds its budget (about 3x the laptop numbers - loose enough for CI,
  tight enough for a lost index or a serialised loop). `ARGUS_TEST_PERF_CHUNKS` scales the
  corpus; `ARGUS_TEST_PERF_REPORT` writes the table.
* **`tests/integration/test_query_plans.py`** records every SELECT/UPDATE/DELETE the platform
  sends during real work (a research job end to end, upload and search, results, monitoring,
  notification and security APIs, scheduler duties) and plans each one with sequential scans
  disabled: a `Seq Scan` on a growing table means no index can serve it.
* **Metrics**: `argus_db_query_duration_seconds{operation}`, `argus_db_pool_connections{state}`
  and `argus_db_pool_capacity` (alert `ArgusDatabasePoolSaturated`),
  `argus_knowledge_retrieval_results`.
* **`scripts/load_test.py`**: read-only GET load against a deployed environment with a
  dedicated key (from the environment, never the command line; https enforced), per-endpoint
  percentiles, 429s counted apart from errors.

## 4. Concurrency
* **Source collection** used to fetch one page after another: a job's collection time was the
  sum of every page's latency. Searches (`search.concurrency`, default 2) and fetches
  (`egress.max_concurrent_fetches`, default 4 - the setting existed but nothing used it) now
  run concurrently per job. Per-host politeness still serialises requests to one site across
  all workers, results are merged in plan order (no timing-dependent source selection), and
  cancellation is checked before every request without exception groups.
* Workers: `worker.concurrency` jobs per process; jobs are claimed with `SKIP LOCKED`, so
  workers scale horizontally without coordination.

## 5. Capacity rules
* **Connections.** Each process opens at most `pool_size + max_overflow` connections. The sum
  over every API, worker and scheduler process must stay below PostgreSQL's
  `max_connections` minus a reserve for migrations and operators. Inside a worker, peak demand is
  about `worker.concurrency x egress.max_concurrent_fetches` short transactions. Beyond what
  PostgreSQL can hold, put PgBouncer in transaction mode in front: tenant context is set with
  `set_config(..., true)` (transaction-local), so pooled connections never leak it.
* **API.** Stateless; scale replicas behind the load balancer; one process per container keeps
  each metrics registry consistent.
* **Workers.** Scale on `argus_queue_depth`; `ARGUS_WORKER__QUEUES` lets a deployment run, for
  example, document parsing on dedicated workers.
* **Vector search.** HNSW (`m`, `ef_construction` in the migration; `ef_search` per query).
  pgvector >= 0.8 iterative scans keep filtered searches complete; build or rebuild the index
  once after bulk loads.
* **Keyword search.** Cost grows with the number of matches; `retrieval.keyword_rank_limit`
  bounds it for very unspecific queries on large projects.
* **Growing tables.** `audit_logs`, `llm_requests`, `tool_calls` and `jobs` grow with traffic.
  Every statement on them is index-served (test above); when they reach hundreds of millions of
  rows, range partitioning by month is the next step (audit verification is per chain and
  unaffected).

## 6. Security
A performance change is accepted only if every security property survives it:
* **Isolation is unchanged.** Folding organisation and project authorisation into one
  transaction keeps both checks and the row-level-security context; the benchmarks and the plan
  check run as the runtime role, so a faster query that only works with RLS off cannot pass.
* **Safety statements stay.** The read-only transaction statement was kept after the probe above
  showed the cheaper alternative was not equivalent.
* **Concurrency does not weaken egress rules.** Every concurrent fetch still goes through the
  SSRF guard, robots.txt and the per-host politeness limit shared by all workers; concurrency is
  bounded per job (`egress.max_concurrent_fetches`), so a large plan cannot become a burst
  against one site or a flood of database connections.
* **The load test is safe to point at a real environment.** GET requests only, a dedicated key
  read from the environment (never from the command line, where it would land in shell
  history), https enforced.
* **Telemetry stays cheap and clean.** Statements are redacted only for spans that are recorded,
  and still always redacted when they are.

## 7. Tests
`tests/perf/test_benchmarks.py` (budgets for search, list endpoints, the security summary and the
queue), `tests/integration/test_query_plans.py` (no sequential scan on a growing table, for every
statement recorded during real work), `tests/integration/test_collection_concurrency.py` (the
fake network counts responses awaited at the same moment: exactly one with one fetch at a time,
several and never more than the bound with four - counted, not timed, so a loaded machine cannot
make it flaky), plus the unchanged retrieval-quality tests and AI evaluation baseline.

## 8. Files
* `modules/research/collection.py` (concurrent collection), `modules/knowledge/retrieval.py`
  (keyword ranking), `modules/tenancy/authorization.py` (single-transaction project
  authorisation), `infrastructure/observability/{metrics,tracing}.py` (pool collector, cheaper
  statement hook), `core/config.py` (`search.concurrency`, `retrieval.keyword_rank_limit`,
  fetch concurrency default; the unused `notifications` worker queue removed).
* `tests/perf/test_benchmarks.py`, `tests/integration/test_query_plans.py`,
  `scripts/load_test.py`, alert `ArgusDatabasePoolSaturated`, dashboard panel "Connection pool
  usage".

## 9. Common mistakes avoided
* Optimising without a profile (the biggest cost - cover-density ranking - was not where
  intuition pointed).
* Benchmarks without warm-up (the first concurrent round measures connection set-up).
* Removing a safety statement for speed without proving the replacement is equivalent.
* A hand-written "hot query" list that drifts from the code.
* Unbounded concurrency (a job with 50 sources must not open 50 connections).

## 10. Next phases
Phase 22 runs the plan check in CI (it is part of the integration suite) and can run the
benchmarks on a schedule; phase 23 sizes pools and replicas with the rules above.

## 11. Acceptance criteria
* `pytest -m perf` meets every budget; the plan check finds no unindexed statement.
* Retrieval-quality tests and the AI evaluation baseline are unchanged.
* Pool occupancy and statement latency are visible per process.
