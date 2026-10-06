"""Phase 20 acceptance: one trace follows a research job across processes, and telemetry never
carries what it must not (objectives, document text, e-mail addresses, tokens, page URLs).

The tracer provider is installed through the production code path (``configure_tracing``) with
an in-memory exporter; everything else is the real stack: API, queue, worker, pipeline, agents
(offline models), SSRF-safe fetcher (fake sockets) and PostgreSQL.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import asyncpg
import pytest
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.trace import SpanKind

from argus.core.config import Settings
from tests.research_world import OBJECTIVE, V1, World, open_world
from tests.support import (
    DatabaseURLs,
    SpanSink,
    api_harness,
    bearer,
    capture_spans,
    register_and_login,
)

pytestmark = pytest.mark.integration
FOREIGN_TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
FOREIGN_PARENT = "00f067aa0ba902b7"


@pytest.fixture
def spans() -> Iterator[SpanSink]:
    sink = capture_spans()
    yield sink
    sink.listening = False
    sink.spans.clear()


@pytest.fixture
async def world(db_settings: Settings, tmp_path: Path) -> AsyncIterator[World]:
    async with open_world(db_settings, tmp_path) as opened:
        yield opened


def one(spans: list[ReadableSpan], name: str, kind: SpanKind | None = None) -> ReadableSpan:
    found = [s for s in spans if s.name == name and (kind is None or s.kind == kind)]
    assert found, f"no span {name!r}; have {sorted({s.name for s in spans})}"
    return found[0]


def named(spans: list[ReadableSpan], prefix: str) -> list[ReadableSpan]:
    return [s for s in spans if s.name.startswith(prefix)]


def ancestors(span: ReadableSpan, by_id: dict[int, ReadableSpan]) -> list[str]:
    names: list[str] = []
    parent = span.parent
    while parent is not None and parent.span_id in by_id:
        current = by_id[parent.span_id]
        names.append(current.name)
        parent = current.parent
    return names


def attribute_values(spans: list[ReadableSpan]) -> list[str]:
    return [str(value) for item in spans for value in (item.attributes or {}).values()]


async def test_one_trace_follows_a_research_job_from_request_to_database(
    world: World, spans: SpanSink
) -> None:
    job = await world.create_job()
    await world.run_jobs()
    assert (await world.job(job["id"]))["status"] == "completed"

    finished = spans.finished()
    request = one(
        finished,
        "POST /api/v1/orgs/{org_id}/projects/{project_id}/research-jobs",
        SpanKind.SERVER,
    )
    trace_id = request.context.trace_id
    in_trace = [s for s in finished if s.context.trace_id == trace_id]
    by_id = {s.context.span_id: s for s in in_trace}

    # The worker continued the request's trace through jobs.trace_parent.
    job_span = one(in_trace, "job research.run")
    assert job_span.kind == SpanKind.CONSUMER
    assert job_span.parent is not None
    assert job_span.parent.span_id == request.context.span_id
    assert job_span.attributes is not None
    assert job_span.attributes["argus.job.outcome"] == "succeeded"

    stages = {s.name for s in named(in_trace, "research.stage ")}
    assert {"research.stage plan", "research.stage collect", "research.stage analyze"} <= stages
    agents = named(in_trace, "agent.run ")
    assert {"agent.run planner", "agent.run analyst"} <= {s.name for s in agents}
    for agent in agents:
        assert "job research.run" in ancestors(agent, by_id)
        assert agent.attributes is not None
        assert agent.attributes["argus.agent.termination"] == "completed"

    llm = named(in_trace, "chat ")
    assert llm, "model calls are traced"
    for call in llm:
        assert call.kind == SpanKind.CLIENT
        assert call.attributes is not None
        assert call.attributes["gen_ai.provider.name"] == "local"
        assert call.attributes["argus.llm.outcome"] == "ok"
        assert any(name.startswith("agent.run ") for name in ancestors(call, by_id))

    fetches = named(in_trace, "egress.fetch")
    assert fetches
    assert all(
        set(f.attributes or {})
        <= {
            "server.address",
            "http.response.status_code",
            "argus.egress.redirects",
            "argus.egress.bytes",
            "argus.egress.outcome",
            "error.type",
        }
        for f in fetches
    )
    assert {f.attributes["server.address"] for f in fetches if f.attributes} == {"news.example.com"}

    statements = named(in_trace, "db ")
    assert statements, "database statements are traced"
    assert any("research.stage " in " ".join(ancestors(s, by_id)) for s in statements)
    assert not any(
        str((s.attributes or {}).get("db.query.text", "")).startswith("SELECT set_config(")
        for s in statements
    )

    # Nothing sensitive in any attribute of any span the job produced.
    values = attribute_values(finished)
    assert not [v for v in values if OBJECTIVE[:40] in v]
    assert not [v for v in values if "@example.com" in v]
    assert not [v for v in values if "Bearer" in v or world.owner[:20] in v]
    assert not [v for v in values if "/market" in v]  # page paths stay out of telemetry
    assert not [v for v in values if "grew 40 percent" in v or "Vendor A" in v]  # page text

    # No trace header ever reached the outside world.
    assert world.net.requests
    assert all("traceparent" not in r.header_names for r in world.net.requests)


async def test_incoming_trace_context_is_continued_only_when_trusted(
    db_settings: Settings, spans: SpanSink
) -> None:
    header = {"traceparent": f"00-{FOREIGN_TRACE}-{FOREIGN_PARENT}-01"}

    async def server_span(settings: Settings) -> ReadableSpan:
        spans.spans.clear()
        async with api_harness(settings) as h:
            _, tokens = await register_and_login(h)
            response = await h.client.get(
                f"{V1}/orgs", headers={**bearer(tokens["access_token"]), **header}
            )
            assert response.status_code == 200
        return one(spans.finished(), "GET /api/v1/orgs", SpanKind.SERVER)

    untrusted = await server_span(db_settings)
    assert format(untrusted.context.trace_id, "032x") != FOREIGN_TRACE
    assert untrusted.parent is None

    trusting = db_settings.model_copy(
        update={
            "observability": db_settings.observability.model_copy(
                update={"trust_incoming_trace_context": True}
            )
        }
    )
    trusted = await server_span(trusting)
    assert format(trusted.context.trace_id, "032x") == FOREIGN_TRACE
    assert trusted.parent is not None
    assert format(trusted.parent.span_id, "016x") == FOREIGN_PARENT
    assert trusted.attributes is not None
    assert trusted.attributes["http.route"] == "/api/v1/orgs"
    assert trusted.attributes["http.response.status_code"] == 200


async def test_job_rows_accept_only_a_well_formed_traceparent(
    database_urls: DatabaseURLs,
) -> None:
    conn = await asyncpg.connect(database_urls.admin)
    try:
        for bad in ("hello", "00-" + "g" * 32 + "-" + "0" * 16 + "-01", "x" * 55):
            with pytest.raises(asyncpg.CheckViolationError):
                await conn.execute(
                    "INSERT INTO jobs (id, queue, task, payload, run_at, max_attempts, timeout_s,"
                    " trace_parent) VALUES (gen_random_uuid(), 'default', 't', '{}', now(), 1, 1,"
                    " $1)",
                    bad,
                )
    finally:
        await conn.close()
