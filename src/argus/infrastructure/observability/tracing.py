"""Distributed tracing with OpenTelemetry.

One trace follows a piece of work across processes::

    HTTP request (api) ─► job (worker, via jobs.trace_parent) ─► research stage
        ─► agent run ─► LLM call / tool call ─► database statements

Design rules, all security-driven:

* **Off unless configured.** Without ``ARGUS_OBSERVABILITY__OTEL_ENABLED`` the global tracer is
  OpenTelemetry's no-op tracer: spans cost almost nothing and go nowhere.
* **Our own instrumentation, no auto-instrumentation of HTTP clients.** Auto-instrumented clients
  inject ``traceparent`` headers into every outgoing request - including fetches of arbitrary
  third-party websites during research, which would leak internal identifiers. Egress spans are
  created by hand and nothing is propagated outside the platform.
* **Attributes are an allow-list.** Spans carry methods, route *templates*, status codes, host
  names, identifiers, model names, token counts and costs - never URLs with queries, prompts,
  document text, e-mail addresses or credentials. SQL text is parameterised and redacted.
* **Incoming trace context is not trusted by default.** A client choosing our trace ids could
  collide with, or splice itself into, other traces; ``trust_incoming_trace_context`` enables it
  behind a gateway that sets the header itself.
"""

from __future__ import annotations

import time
import weakref
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any, Final

from opentelemetry import context as otel_context
from opentelemetry import propagate, trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter
from opentelemetry.sdk.trace.sampling import ParentBasedTraceIdRatio
from opentelemetry.trace import Span, SpanKind, Status, StatusCode
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine
from structlog.types import EventDict, WrappedLogger

from argus.core.config import ObservabilitySettings
from argus.core.logging import get_logger
from argus.core.redaction import redact_text
from argus.infrastructure.observability.metrics import Metrics

TRACER_NAME: Final = "argus"
_PROPAGATOR: Final = TraceContextTextMapPropagator()
_MAX_STATEMENT_CHARS: Final = 1_000
_SKIPPED_STATEMENTS: Final = ("SELECT set_config(", "SET TRANSACTION")
_instrumented: weakref.WeakSet[Any] = weakref.WeakSet()
log = get_logger(__name__)


def tracer() -> trace.Tracer:
    """The platform's tracer (a no-op until :func:`configure_tracing` installs a provider)."""
    return trace.get_tracer(TRACER_NAME)


def configure_tracing(
    settings: ObservabilitySettings,
    *,
    service: str,
    version: str,
    environment: str,
    exporter: SpanExporter | None = None,
) -> TracerProvider | None:
    """Install the process-wide tracer provider once. Returns it, or ``None`` when tracing is
    disabled or a provider was already installed (tests install their own first)."""
    if exporter is None and not (settings.otel_enabled and settings.otel_endpoint):
        return None
    if not isinstance(trace.get_tracer_provider(), trace.ProxyTracerProvider):
        return None
    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": service,
                "service.version": version,
                "deployment.environment.name": environment,
            }
        ),
        sampler=ParentBasedTraceIdRatio(settings.otel_sample_ratio),
    )
    provider.add_span_processor(BatchSpanProcessor(exporter or _otlp_exporter(settings)))
    trace.set_tracer_provider(provider)
    propagate.set_global_textmap(_PROPAGATOR)
    log.info("tracing.enabled", service=service, sample_ratio=settings.otel_sample_ratio)
    return provider


def _otlp_exporter(settings: ObservabilitySettings) -> SpanExporter:
    import requests
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    session = requests.Session()
    session.trust_env = False  # never route telemetry through proxy variables (threat W7)
    headers: dict[str, str] = {}
    if settings.otel_headers is not None:
        for part in settings.otel_headers.get_secret_value().split(","):
            name, _, value = part.partition("=")
            if name.strip() and value.strip():
                headers[name.strip().lower()] = value.strip()
    endpoint = str(settings.otel_endpoint).rstrip("/") + "/v1/traces"
    return OTLPSpanExporter(endpoint=endpoint, headers=headers, timeout=5, session=session)


def shutdown_tracing() -> None:
    provider = trace.get_tracer_provider()
    shutdown = getattr(provider, "shutdown", None)
    if callable(shutdown):
        shutdown()


# ------------------------------------------------------------------------- propagation
def current_traceparent() -> str | None:
    """The W3C ``traceparent`` of the active span, to carry work across the job queue."""
    carrier: dict[str, str] = {}
    _PROPAGATOR.inject(carrier)
    return carrier.get("traceparent")


def context_from_traceparent(value: str | None) -> otel_context.Context | None:
    if not value:
        return None
    extracted = _PROPAGATOR.extract({"traceparent": value})
    span_context = trace.get_current_span(extracted).get_span_context()
    return extracted if span_context.is_valid else None


def context_from_headers(headers: Mapping[str, str]) -> otel_context.Context | None:
    value = headers.get("traceparent")
    if value is None:
        return None
    carrier = {"traceparent": value}
    if (state := headers.get("tracestate")) is not None:
        carrier["tracestate"] = state
    extracted = _PROPAGATOR.extract(carrier)
    return extracted if trace.get_current_span(extracted).get_span_context().is_valid else None


# ---------------------------------------------------------------------------- spans
@contextmanager
def span(
    name: str,
    *,
    kind: SpanKind = SpanKind.INTERNAL,
    attributes: Mapping[str, Any] | None = None,
    parent: otel_context.Context | None = None,
    expected: tuple[type[BaseException], ...] = (),
) -> Iterator[Span]:
    """Start a span as the current one. Exceptions are recorded by type only (their messages can
    contain user data) and re-raised; ``expected`` ones (control flow such as "waiting for an
    approval") are noted without marking the span as failed."""
    with tracer().start_as_current_span(
        name,
        context=parent,
        kind=kind,
        attributes=_clean(attributes),
        record_exception=False,
        set_status_on_exception=False,
    ) as current:
        try:
            yield current
        except expected as exc:
            current.set_attribute("argus.outcome", type(exc).__name__)
            raise
        except BaseException as exc:
            current.set_status(Status(StatusCode.ERROR, type(exc).__name__))
            current.set_attribute("error.type", type(exc).__name__)
            raise


def record_span(
    name: str,
    *,
    duration_s: float,
    kind: SpanKind = SpanKind.INTERNAL,
    attributes: Mapping[str, Any] | None = None,
    error: bool = False,
) -> None:
    """A span for something that already happened (it ended now and lasted ``duration_s``)."""
    end = time.time_ns()
    finished = tracer().start_span(
        name,
        kind=kind,
        attributes=_clean(attributes),
        start_time=end - max(0, int(duration_s * 1_000_000_000)),
    )
    if error:
        finished.set_status(Status(StatusCode.ERROR))
    finished.end(end_time=end)


def set_attributes(target: Span, attributes: Mapping[str, Any]) -> None:
    for key, value in _clean(attributes).items():
        target.set_attribute(key, value)


def _clean(attributes: Mapping[str, Any] | None) -> dict[str, Any]:
    """OpenTelemetry accepts str/bool/int/float (and sequences of them); drop ``None`` and
    stringify everything else (UUIDs, decimals) so a stray type can never break a request."""
    cleaned: dict[str, Any] = {}
    for key, value in (attributes or {}).items():
        if value is None:
            continue
        cleaned[key] = value if isinstance(value, str | bool | int | float) else str(value)
    return cleaned


# ---------------------------------------------------------------------- log correlation
def add_trace_ids(_: WrappedLogger, __: str, event_dict: EventDict) -> EventDict:
    """structlog processor: put the active trace and span ids on every log line."""
    span_context = trace.get_current_span().get_span_context()
    if span_context.is_valid:
        event_dict.setdefault("trace_id", format(span_context.trace_id, "032x"))
        event_dict.setdefault("span_id", format(span_context.span_id, "016x"))
    return event_dict


# ------------------------------------------------------------------------- database
def _operation(statement: str) -> str:
    word = statement.lstrip().split(None, 1)[0].upper() if statement.strip() else "OTHER"
    return word if word in {"SELECT", "INSERT", "UPDATE", "DELETE", "WITH"} else "OTHER"


def instrument_database(engine: AsyncEngine, metrics: Metrics | None) -> None:
    """Statement spans (children of whatever span is current) and a latency histogram by
    operation. Idempotent per engine. Transaction-setup statements are timed but not traced."""
    sync_engine = engine.sync_engine
    if sync_engine in _instrumented:
        return
    _instrumented.add(sync_engine)

    @event.listens_for(sync_engine, "before_cursor_execute")
    def _before(
        conn: Any, cursor: Any, statement: str, parameters: Any, context: Any, executemany: bool
    ) -> None:
        del conn, cursor, parameters, executemany
        operation = _operation(statement)
        started = time.perf_counter()
        active: Span | None = None
        if not statement.startswith(_SKIPPED_STATEMENTS):
            active = tracer().start_span(f"db {operation}", kind=SpanKind.CLIENT)
            if active.is_recording():  # no redaction work for disabled or sampled-out traces
                active.set_attributes(
                    {
                        "db.system.name": "postgresql",
                        "db.operation.name": operation,
                        "db.query.text": redact_text(statement[:_MAX_STATEMENT_CHARS]),
                    }
                )
        if context is not None:
            context._argus_trace = (operation, started, active)

    @event.listens_for(sync_engine, "after_cursor_execute")
    def _after(
        conn: Any, cursor: Any, statement: str, parameters: Any, context: Any, executemany: bool
    ) -> None:
        del conn, cursor, statement, parameters, executemany
        _finish(context, metrics, failed=False)

    @event.listens_for(sync_engine, "handle_error")
    def _error(exception_context: Any) -> None:
        _finish(exception_context.execution_context, metrics, failed=True)


def _finish(context: Any, metrics: Metrics | None, *, failed: bool) -> None:
    state = getattr(context, "_argus_trace", None)
    if state is None:
        return
    context._argus_trace = None
    operation, started, active = state
    if metrics is not None:
        metrics.db_latency.labels(operation).observe(time.perf_counter() - started)
    if active is not None:
        if failed:
            active.set_status(Status(StatusCode.ERROR))
        active.end()
