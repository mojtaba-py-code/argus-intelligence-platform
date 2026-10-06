"""Process start-up shared by the API, worker, scheduler and CLI: logging and tracing."""

from __future__ import annotations

import asyncio
import contextlib
from typing import Literal

from opentelemetry.sdk.trace import TracerProvider
from sqlalchemy import text

from argus import __version__
from argus.core.config import Settings
from argus.core.logging import configure_logging, get_logger
from argus.infrastructure.db import Database
from argus.infrastructure.db.migrations import schema_state
from argus.infrastructure.observability.tracing import add_trace_ids, configure_tracing

log = get_logger(__name__)

Role = Literal["api", "worker", "scheduler", "cli"]


def start_observability(settings: Settings, role: Role) -> TracerProvider | None:
    """Configure logging (with trace correlation) and, when enabled, tracing. Returns the tracer
    provider this call installed, so the caller can flush it on shutdown."""
    obs = settings.observability
    service = obs.service_name if role == "api" else f"{obs.service_name}-{role}"
    configure_logging(
        level=obs.log_level, fmt=obs.log_format, service=service, processors=[add_trace_ids]
    )
    return configure_tracing(
        obs, service=service, version=__version__, environment=settings.environment.value
    )


async def wait_for_schema(
    database: Database, stop: asyncio.Event, *, interval_s: float = 5.0
) -> bool:
    """Block until the database is at (or ahead of) this build's migration head.

    Workers and the scheduler have no readiness probe to hold them back during a rollout: without
    this, a new worker could claim jobs before the release's migration Job has finished. Returns
    ``False`` when ``stop`` is set first.
    """
    logged = False
    while not stop.is_set():
        try:
            async with database.session(read_only=True) as session:
                current = (
                    await session.execute(text("SELECT version_num FROM alembic_version"))
                ).scalar_one_or_none()
        except Exception as exc:  # noqa: BLE001 - not reachable yet: keep waiting, log once
            current = None
            if not logged:
                log.warning("process.database_unavailable", error_type=type(exc).__name__)
        if current is not None and schema_state(str(current)) == "ok":
            return True
        if not logged:
            log.info("process.waiting_for_migrations", current=current)
            logged = True
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), interval_s)
    return False
