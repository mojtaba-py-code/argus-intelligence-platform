"""Phase 20 units: tracing helpers, log correlation, the worker/scheduler metrics endpoint,
production guards for telemetry settings."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterator

import httpx
import pytest
from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

from argus.apps.ops_server import ops_app, serve_ops
from argus.infrastructure.observability.metrics import Metrics
from argus.infrastructure.observability.tracing import (
    _operation,
    add_trace_ids,
    configure_tracing,
    context_from_headers,
    context_from_traceparent,
    current_traceparent,
    record_span,
    span,
)
from tests.support import SpanSink, capture_spans, make_settings

# Flags are two hex digits: SDKs set 01 (sampled) and, per Trace Context Level 2, 02 (random id).
TRACEPARENT = re.compile(r"^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$")


@pytest.fixture
def spans() -> Iterator[SpanSink]:
    sink = capture_spans()
    yield sink
    sink.listening = False
    sink.spans.clear()


# ---------------------------------------------------------------------------------- spans
def test_traceparent_round_trip(spans: SpanSink) -> None:
    assert current_traceparent() is None  # nothing to propagate outside a span
    with span("outer") as outer:
        value = current_traceparent()
    assert value is not None
    assert TRACEPARENT.match(value)
    restored = context_from_traceparent(value)
    assert restored is not None
    with span("continued", parent=restored):
        pass
    finished = {s.name: s for s in spans.finished()}
    continued = finished["continued"]
    assert continued.context.trace_id == outer.get_span_context().trace_id
    assert continued.parent is not None
    assert continued.parent.span_id == outer.get_span_context().span_id


@pytest.mark.parametrize(
    "value", [None, "", "garbage", "00-" + "0" * 32 + "-" + "0" * 16 + "-01", "ff-x-y-z"]
)
def test_invalid_traceparents_are_ignored(value: str | None) -> None:
    assert context_from_traceparent(value) is None
    assert context_from_headers({"traceparent": value or ""}) is None
    assert context_from_headers({}) is None


def test_span_records_errors_by_type_only(spans: SpanSink) -> None:
    secret = "password=hunter2 for alice@example.com"
    with pytest.raises(ValueError, match="hunter2"), span("failing"):
        raise ValueError(secret)
    with pytest.raises(KeyError), span("expected", expected=(KeyError,)):
        raise KeyError("approval")
    finished = {s.name: s for s in spans.finished()}
    failing = finished["failing"]
    assert failing.status.status_code == StatusCode.ERROR
    assert failing.attributes is not None
    assert failing.attributes["error.type"] == "ValueError"
    assert not failing.events  # no exception event: messages can carry user data
    assert "hunter2" not in str(failing.attributes)
    expected = finished["expected"]
    assert expected.status.status_code == StatusCode.UNSET
    assert expected.attributes is not None
    assert expected.attributes["argus.outcome"] == "KeyError"


def test_attributes_are_coerced_and_none_dropped(spans: SpanSink) -> None:
    from decimal import Decimal
    from uuid import uuid4

    identifier = uuid4()
    with span("typed", attributes={"a": identifier, "b": Decimal("1.5"), "c": None, "d": 3}):
        pass
    attributes = dict(spans.finished()[-1].attributes or {})
    assert attributes == {"a": str(identifier), "b": "1.5", "d": 3}


def test_record_span_has_the_given_duration(spans: SpanSink) -> None:
    record_span("chat model", duration_s=2.5, kind=SpanKind.CLIENT, error=True)
    finished = spans.finished()[-1]
    assert finished.end_time is not None
    assert finished.start_time is not None
    assert abs((finished.end_time - finished.start_time) / 1e9 - 2.5) < 0.01
    assert finished.status.status_code == StatusCode.ERROR


@pytest.mark.parametrize(
    ("statement", "operation"),
    [
        ("SELECT 1", "SELECT"),
        ("  insert into x values (1)", "INSERT"),
        ("WITH a AS (SELECT 1) SELECT * FROM a", "WITH"),
        ("UPDATE t SET a = 1", "UPDATE"),
        ("DELETE FROM t", "DELETE"),
        ("VACUUM", "OTHER"),
        ("", "OTHER"),
    ],
)
def test_statement_operation_is_a_bounded_label(statement: str, operation: str) -> None:
    assert _operation(statement) == operation


# ------------------------------------------------------------------------ log correlation
def test_logs_carry_trace_ids_inside_spans(spans: SpanSink) -> None:
    del spans
    assert add_trace_ids(None, "info", {"event": "x"}) == {"event": "x"}
    with span("logging") as current:
        event = add_trace_ids(None, "info", {"event": "x"})
    context = current.get_span_context()
    assert event["trace_id"] == format(context.trace_id, "032x")
    assert event["span_id"] == format(context.span_id, "016x")


# ------------------------------------------------------------------------ configuration
def test_tracing_is_off_unless_configured() -> None:
    disabled = make_settings().observability
    assert configure_tracing(disabled, service="s", version="v", environment="testing") is None


def test_an_installed_provider_is_never_replaced(spans: SpanSink) -> None:
    del spans
    provider = trace.get_tracer_provider()
    enabled = make_settings(
        observability={"otel_enabled": True, "otel_endpoint": "http://collector:4318"}
    ).observability
    assert configure_tracing(enabled, service="s", version="v", environment="testing") is None
    assert trace.get_tracer_provider() is provider


# --------------------------------------------------------------- worker metrics endpoint
async def test_ops_endpoint_requires_the_metrics_token() -> None:
    metrics = Metrics()
    metrics.jobs.labels("default", "t", "succeeded").inc()
    settings = make_settings(observability={"metrics_token": "scrape-token-" + "x" * 20})
    app = ops_app(settings.observability, metrics)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://worker"
    ) as client:
        assert (await client.get("/metrics")).status_code == 401
        wrong = await client.get("/metrics", headers={"Authorization": "Bearer nope"})
        assert wrong.status_code == 401
        ok = await client.get(
            "/metrics", headers={"Authorization": "Bearer scrape-token-" + "x" * 20}
        )
        assert ok.status_code == 200
        assert "argus_jobs_total" in ok.text
        assert (await client.get("/health/live")).text == "ok"
        assert (await client.get("/anything-else")).status_code == 404


async def test_ops_endpoint_is_not_started_without_a_port() -> None:
    stop = asyncio.Event()
    await asyncio.wait_for(serve_ops(make_settings().observability, Metrics(), stop), 1)
