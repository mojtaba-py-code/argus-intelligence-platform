"""Prometheus metrics.

Each process owns one :class:`Metrics` instance with its own ``CollectorRegistry`` (no global
state, so tests can build many apps). Label values are always bounded sets - route *templates*,
never raw paths, ids or user input - to keep cardinality and privacy under control.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
from prometheus_client.core import GaugeMetricFamily, Metric
from prometheus_client.registry import Collector

_LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60)
_LONG_BUCKETS = (1, 5, 15, 30, 60, 120, 300, 600, 1200, 2400, 3600)


class PoolCollector(Collector):
    """Connection-pool occupancy, read from the pool at scrape time (no background polling).

    Sizing rule this makes measurable: ``pool_size + max_overflow`` per process, times the
    number of processes, must stay below PostgreSQL's ``max_connections`` minus a reserve - and
    checked-out connections close to capacity mean requests are queuing for a connection.
    """

    def __init__(self, namespace: str) -> None:
        self._prefix = namespace
        self._pool: Any = None
        self._capacity = 0

    def watch(self, pool: Any, *, capacity: int) -> None:
        self._pool = pool
        self._capacity = capacity

    def collect(self) -> Iterator[Metric]:
        connections = GaugeMetricFamily(
            f"{self._prefix}_db_pool_connections",
            "Database pool connections by state",
            labels=["state"],
        )
        capacity = GaugeMetricFamily(
            f"{self._prefix}_db_pool_capacity",
            "Most connections this process may open (pool_size + max_overflow)",
        )
        pool = self._pool
        if pool is not None and hasattr(pool, "checkedout"):
            connections.add_metric(["checked_out"], float(pool.checkedout()))
            connections.add_metric(["idle"], float(pool.checkedin()))
            connections.add_metric(["overflow"], float(max(0, pool.overflow())))
            capacity.add_metric([], float(self._capacity))
        yield connections
        yield capacity


class Metrics:
    def __init__(self, namespace: str = "argus") -> None:
        self.registry = CollectorRegistry(auto_describe=True)
        ns = namespace
        r = self.registry
        self.http_requests = Counter(
            "http_requests",
            "HTTP requests",
            ["method", "route", "status"],
            namespace=ns,
            registry=r,
        )
        self.http_latency = Histogram(
            "http_request_duration_seconds",
            "HTTP request latency",
            ["method", "route"],
            namespace=ns,
            registry=r,
            buckets=_LATENCY_BUCKETS,
        )
        self.rate_limited = Counter(
            "rate_limited",
            "Rate-limit decisions that refused (or, for politeness, delayed) an action",
            ["policy"],
            namespace=ns,
            registry=r,
        )
        self.ratelimit_degraded = Counter(
            "ratelimit_degraded",
            "Rate-limit checks served by the local fallback",
            namespace=ns,
            registry=r,
        )
        self.jobs = Counter(
            "jobs", "Queue job outcomes", ["queue", "task", "outcome"], namespace=ns, registry=r
        )
        self.job_duration = Histogram(
            "job_duration_seconds",
            "Job run time",
            ["task"],
            namespace=ns,
            registry=r,
            buckets=_LONG_BUCKETS,
        )
        self.queue_depth = Gauge(
            "queue_depth", "Queued jobs by queue", ["queue"], namespace=ns, registry=r
        )
        self.research_duration = Histogram(
            "research_duration_seconds",
            "Research job duration",
            ["outcome"],
            namespace=ns,
            registry=r,
            buckets=_LONG_BUCKETS,
        )
        self.llm_tokens = Counter(
            "llm_tokens", "LLM tokens", ["provider", "model", "direction"], namespace=ns, registry=r
        )
        self.llm_cost = Counter(
            "llm_cost_usd", "LLM cost in USD", ["provider", "model"], namespace=ns, registry=r
        )
        self.llm_requests = Counter(
            "llm_requests",
            "LLM calls",
            ["provider", "model", "task", "outcome"],
            namespace=ns,
            registry=r,
        )
        self.llm_latency = Histogram(
            "llm_request_duration_seconds",
            "LLM latency",
            ["provider", "model"],
            namespace=ns,
            registry=r,
            buckets=_LATENCY_BUCKETS,
        )
        self.fetches = Counter(
            "fetches", "Outbound fetch outcomes", ["outcome"], namespace=ns, registry=r
        )
        self.egress_blocked = Counter(
            "egress_blocked",
            "Outbound requests blocked by the SSRF guard",
            ["reason"],
            namespace=ns,
            registry=r,
        )
        self.injection_detections = Counter(
            "injection_detections",
            "Untrusted content classified by injection risk",
            ["level"],
            namespace=ns,
            registry=r,
        )
        self.documents = Counter(
            "documents",
            "Document lifecycle events (uploaded, ready, quarantined, failed, deleted)",
            ["event"],
            namespace=ns,
            registry=r,
        )
        self.document_parse = Histogram(
            "document_parse_duration_seconds",
            "Sandboxed parse time per document kind",
            ["kind", "outcome"],
            namespace=ns,
            registry=r,
            buckets=(0.25, 0.5, 1, 2, 5, 10, 30, 60, 120),
        )
        self.chunks_indexed = Counter(
            "knowledge_chunks_indexed",
            "Chunks written to the knowledge store",
            ["origin", "embedded"],
            namespace=ns,
            registry=r,
        )
        self.retrievals = Counter(
            "knowledge_retrievals",
            "Hybrid retrieval requests",
            ["mode", "cache"],
            namespace=ns,
            registry=r,
        )
        self.agent_runs = Counter(
            "agent_runs",
            "Agent runs by termination reason",
            ["agent", "termination"],
            namespace=ns,
            registry=r,
        )
        self.tool_calls = Counter(
            "agent_tool_calls",
            "Agent tool calls",
            ["agent", "tool", "outcome"],
            namespace=ns,
            registry=r,
        )
        self.retrieval_latency = Histogram(
            "retrieval_duration_seconds",
            "Hybrid retrieval latency",
            namespace=ns,
            registry=r,
            buckets=_LATENCY_BUCKETS,
        )
        self.access_denied = Counter(
            "access_denied",
            "Permission denials of organisation members (recorded = written to the audit log)",
            ["recorded"],
            namespace=ns,
            registry=r,
        )
        self.audit_verifications = Counter(
            "audit_verifications",
            "Organisation audit chain verifications",
            ["result"],
            namespace=ns,
            registry=r,
        )
        self.db_latency = Histogram(
            "db_query_duration_seconds",
            "Database statement latency by operation (ping = readiness probe)",
            ["operation"],
            namespace=ns,
            registry=r,
            buckets=_LATENCY_BUCKETS,
        )
        self.retrieval_results = Histogram(
            "knowledge_retrieval_results",
            "Chunks returned per retrieval (0 = nothing relevant was found)",
            ["mode"],
            namespace=ns,
            registry=r,
            buckets=(0, 1, 2, 3, 5, 8, 12, 20, 50),
        )
        self.scheduler_runs = Counter(
            "scheduler_task_runs",
            "Periodic task runs by outcome",
            ["task", "outcome"],
            namespace=ns,
            registry=r,
        )

        self.db_pool = PoolCollector(ns)
        r.register(self.db_pool)

    def render(self) -> bytes:
        return generate_latest(self.registry)
