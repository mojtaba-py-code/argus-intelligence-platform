"""``argus worker`` - consume the durable queue.

Wake-up is push-first (PostgreSQL ``LISTEN argus_jobs`` on a dedicated connection) with polling as
the fallback, so an idle worker reacts within milliseconds without hammering the database.
SIGTERM/SIGINT trigger a graceful drain (see :class:`argus.infrastructure.queue.worker.Worker`).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import socket

from argus.apps.container import Container, build_container
from argus.apps.ops_server import serve_ops
from argus.apps.process import start_observability, wait_for_schema
from argus.core.config import Settings
from argus.core.ids import random_lower_alnum
from argus.core.logging import get_logger
from argus.infrastructure.queue.queue import NOTIFY_CHANNEL
from argus.infrastructure.queue.worker import Worker, WorkerConfig

log = get_logger(__name__)


def worker_id() -> str:
    return f"{socket.gethostname()[:40]}:{os.getpid()}:{random_lower_alnum(6)}"


def build_worker(container: Container, *, queues: tuple[str, ...] | None = None) -> Worker:
    settings = container.settings.worker
    return Worker(
        queue=container.queue,
        registry=container.tasks,
        services=container,
        config=WorkerConfig(
            worker_id=worker_id(),
            queues=queues or settings.queues,
            concurrency=settings.concurrency,
            lease_s=settings.lease_s,
            heartbeat_s=settings.heartbeat_s,
            poll_interval_s=settings.poll_interval_s,
            shutdown_grace_s=settings.shutdown_grace_s,
        ),
        metrics=container.metrics,
    )


async def run_worker(settings: Settings) -> None:
    provider = start_observability(settings, "worker")
    container = build_container(settings, role="worker")
    worker = build_worker(container)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):  # Windows: signal handlers unsupported
            loop.add_signal_handler(signum, stop.set)
    listener = None
    ops = asyncio.create_task(serve_ops(settings.observability, container.metrics, stop))
    try:
        try:
            listener = await container.database.connect_raw("argus-worker-listen")
            await listener.add_listener(NOTIFY_CHANNEL, lambda *_: worker.wake())
        except Exception as exc:  # noqa: BLE001 - polling still works without LISTEN
            log.warning("worker.listen_unavailable", error_type=type(exc).__name__)
        if await wait_for_schema(container.database, stop):
            await worker.run(stop)
    finally:
        stop.set()
        await ops
        if listener is not None and not listener.is_closed():
            await listener.close()
        await container.aclose()
        if provider is not None:
            provider.shutdown()
