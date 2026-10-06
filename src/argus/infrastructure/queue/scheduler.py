"""Leader-elected periodic scheduler.

Exactly one scheduler instance is *active*: it holds a session-level PostgreSQL advisory lock on a
dedicated connection. If that process dies, its connection closes, the lock is released, and a
standby acquires it within ``retry_s`` - no external coordinator (ZooKeeper, etcd) needed.
Periodic work is idempotent (re-queue expired leases, enqueue due monitors with dedup keys...),
so a brief overlap during fail-over is harmless.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

import asyncpg

from argus.core.logging import get_logger
from argus.infrastructure.db import Database
from argus.infrastructure.observability.metrics import Metrics
from argus.infrastructure.observability.tracing import span

log = get_logger(__name__)
LEADER_LOCK_KEY = 0x41524755_53000001  # "ARGUS" + 1, a stable 64-bit advisory-lock key


@dataclass
class PeriodicTask:
    name: str
    interval_s: float
    run: Callable[[], Awaitable[None]]
    timeout_s: float = 300.0
    last_run: float = field(default=float("-inf"))


class LeaderLock:
    def __init__(self, database: Database, *, key: int = LEADER_LOCK_KEY) -> None:
        self._database = database
        self._key = key
        self._connection: asyncpg.Connection | None = None

    @property
    def held(self) -> bool:
        return self._connection is not None and not self._connection.is_closed()

    async def try_acquire(self) -> bool:
        if self.held:
            return True
        connection = await self._database.connect_raw("argus-scheduler-leader")
        acquired = bool(await connection.fetchval("SELECT pg_try_advisory_lock($1)", self._key))
        if acquired:
            self._connection = connection
        else:
            await connection.close()
        return acquired

    async def verify(self) -> bool:
        """Confirm the connection (and therefore the lock) is still alive."""
        if self._connection is None:
            return False
        try:
            await self._connection.fetchval("SELECT 1")
        except (asyncpg.PostgresError, OSError, asyncpg.InterfaceError):
            await self.release()
            return False
        return True

    async def release(self) -> None:
        connection, self._connection = self._connection, None
        if connection is not None and not connection.is_closed():
            with contextlib.suppress(Exception):
                await connection.execute("SELECT pg_advisory_unlock($1)", self._key)
            await connection.close()


class PeriodicScheduler:
    def __init__(
        self,
        tasks: list[PeriodicTask],
        *,
        leader: LeaderLock,
        tick_s: float = 1.0,
        retry_s: float = 10.0,
        metrics: Metrics | None = None,
    ) -> None:
        self._tasks = tasks
        self._leader = leader
        self._metrics = metrics
        self._tick_s = tick_s
        self._retry_s = retry_s

    async def run(self, stop: asyncio.Event) -> None:
        try:
            while not stop.is_set():
                if not await self._ensure_leadership():
                    await _sleep_or_stop(stop, self._retry_s)
                    continue
                await self.run_due()
                await _sleep_or_stop(stop, self._tick_s)
        finally:
            await self._leader.release()

    async def _ensure_leadership(self) -> bool:
        if self._leader.held:
            return await self._leader.verify()
        try:
            acquired = await self._leader.try_acquire()
        except (OSError, asyncpg.PostgresError) as exc:
            log.warning("scheduler.leader_check_failed", error_type=type(exc).__name__)
            return False
        if acquired:
            log.info("scheduler.became_leader")
        return acquired

    async def run_due(self) -> list[str]:
        ran: list[str] = []
        now = time.monotonic()
        for task in self._tasks:
            if now - task.last_run < task.interval_s:
                continue
            task.last_run = now
            outcome = "ok"
            try:
                with span(f"scheduler {task.name}", attributes={"argus.task": task.name}):
                    async with asyncio.timeout(task.timeout_s):
                        await task.run()
                ran.append(task.name)
            except Exception as exc:  # noqa: BLE001 - one failing duty must not stop the others
                outcome = "failed"
                log.error("scheduler.task_failed", task=task.name, error_type=type(exc).__name__)
            if self._metrics is not None:
                self._metrics.scheduler_runs.labels(task.name, outcome).inc()
        return ran


async def _sleep_or_stop(stop: asyncio.Event, seconds: float) -> None:
    with contextlib.suppress(TimeoutError):
        async with asyncio.timeout(seconds):
            await stop.wait()
