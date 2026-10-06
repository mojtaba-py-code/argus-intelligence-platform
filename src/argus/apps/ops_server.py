"""``/metrics`` and ``/health/live`` for processes that have no API: workers and the scheduler.

Most of the platform's interesting numbers - jobs, LLM tokens and cost, agent runs, tool calls,
fetches, queue depth - are produced in those processes, each with its own registry, so each must
be scraped. The endpoint is a tiny Starlette app on uvicorn (no hand-written HTTP parsing),
embedded in the process's event loop, protected by the same bearer token as the API's
``/metrics``, and bound to ``127.0.0.1`` unless configured otherwise.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Iterator

import uvicorn
from prometheus_client import CONTENT_TYPE_LATEST
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route

from argus.core.config import ObservabilitySettings
from argus.core.crypto import constant_time_equals
from argus.core.logging import get_logger
from argus.infrastructure.observability.metrics import Metrics

log = get_logger(__name__)


class _EmbeddedServer(uvicorn.Server):
    """uvicorn without its own signal handling: the host process owns SIGTERM/SIGINT."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


def ops_app(settings: ObservabilitySettings, metrics: Metrics) -> Starlette:
    expected = (
        f"Bearer {settings.metrics_token.get_secret_value()}"
        if settings.metrics_token is not None
        else None
    )

    async def scrape(request: Request) -> Response:
        if expected is not None and not constant_time_equals(
            request.headers.get("authorization", ""), expected
        ):
            return PlainTextResponse(
                "authentication required", 401, headers={"WWW-Authenticate": "Bearer"}
            )
        return Response(metrics.render(), media_type=CONTENT_TYPE_LATEST)

    async def live(_: Request) -> Response:
        return PlainTextResponse("ok")

    return Starlette(routes=[Route("/metrics", scrape), Route("/health/live", live)])


async def serve_ops(settings: ObservabilitySettings, metrics: Metrics, stop: asyncio.Event) -> None:
    """Serve until ``stop`` is set; returns immediately when no port is configured."""
    if settings.metrics_port is None or not settings.metrics_enabled:
        return
    server = _EmbeddedServer(
        uvicorn.Config(
            ops_app(settings, metrics),
            host=settings.metrics_host,
            port=settings.metrics_port,
            lifespan="off",
            access_log=False,
            log_config=None,
            server_header=False,
            date_header=False,
        )
    )
    task = asyncio.create_task(server.serve())
    log.info("ops_server.started", host=settings.metrics_host, port=settings.metrics_port)
    try:
        await stop.wait()
    finally:
        server.should_exit = True
        with contextlib.suppress(asyncio.CancelledError):
            await task
