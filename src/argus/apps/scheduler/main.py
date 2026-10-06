"""``argus scheduler`` - periodic platform duties, run by exactly one active instance."""

from __future__ import annotations

import asyncio
import contextlib
import signal

from argus.apps.container import Container, build_container
from argus.apps.ops_server import serve_ops
from argus.apps.process import start_observability, wait_for_schema
from argus.core.config import Settings
from argus.core.logging import get_logger
from argus.infrastructure.queue.scheduler import LeaderLock, PeriodicScheduler, PeriodicTask
from argus.modules.identity.maintenance import purge_expired_credentials

log = get_logger(__name__)


def periodic_tasks(container: Container) -> list[PeriodicTask]:
    async def reap() -> None:
        reaped = await container.queue.reap_expired()
        if reaped:
            log.warning("queue.leases_reaped", count=len(reaped))

    async def queue_depth() -> None:
        for queue, depth in (await container.queue.depth()).items():
            container.metrics.queue_depth.labels(queue).set(depth)

    async def idempotency_sweep() -> None:
        await container.idempotency.sweep(container.database)

    async def credentials_sweep() -> None:
        await purge_expired_credentials(container.database, container.clock.now())

    async def monitors_dispatch() -> None:
        dispatched = await container.monitors.dispatch_due()
        if dispatched:
            log.info("monitoring.dispatched", count=dispatched)

    async def notifications_purge() -> None:
        await container.notifications.purge_read()

    async def retention_sweep() -> None:
        await container.retention.sweep()

    async def purge_organizations() -> None:
        purged = await container.lifecycle.purge_due()
        if purged:
            log.info("organizations.purged", count=purged)

    async def audit_verification() -> None:
        verified = await container.integrity.verify_due()
        if verified:
            log.info("audit.verifications_completed", count=verified)

    return [
        PeriodicTask("queue.reap_expired_leases", 15, reap),
        PeriodicTask("queue.depth_metrics", 15, queue_depth),
        PeriodicTask("idempotency.sweep", 3600, idempotency_sweep),
        PeriodicTask("identity.purge_expired_credentials", 3600, credentials_sweep),
        PeriodicTask(
            "monitoring.dispatch",
            container.settings.monitoring.dispatch_interval_s,
            monitors_dispatch,
        ),
        PeriodicTask("notifications.purge_read", 86_400, notifications_purge),
        PeriodicTask("platform.retention", 86_400, retention_sweep),
        PeriodicTask("platform.purge_organizations", 3600, purge_organizations),
        PeriodicTask(
            "security.audit_verification",
            container.settings.security.audit_verify_check_s,
            audit_verification,
        ),
    ]


async def run_scheduler(settings: Settings) -> None:
    provider = start_observability(settings, "scheduler")
    container = build_container(settings, role="scheduler")
    scheduler = PeriodicScheduler(
        periodic_tasks(container),
        leader=LeaderLock(container.database),
        metrics=container.metrics,
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(signum, stop.set)
    ops = asyncio.create_task(serve_ops(settings.observability, container.metrics, stop))
    try:
        if await wait_for_schema(container.database, stop):
            await scheduler.run(stop)
    finally:
        stop.set()
        await ops
        await container.aclose()
        if provider is not None:
            provider.shutdown()
