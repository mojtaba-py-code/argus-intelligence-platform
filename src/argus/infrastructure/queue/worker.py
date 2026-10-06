"""The job runner used by ``argus worker``.

Per job: validate the payload, run the handler under a deadline, extend the lease with a
heartbeat, and record the outcome with a *fenced* update. If the heartbeat discovers that the
lease was lost (the job was reaped and re-claimed elsewhere), the handler is cancelled and its
result discarded - two workers never both "finish" the same attempt.

Graceful shutdown: stop claiming, give running jobs ``shutdown_grace_s`` to finish, then cancel
the rest and *release* them (back to ``queued`` without consuming an attempt).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, Status, StatusCode
from pydantic import ValidationError

from argus.core import context
from argus.core.logging import get_logger
from argus.core.redaction import redact_text
from argus.infrastructure.observability.metrics import Metrics
from argus.infrastructure.observability.tracing import context_from_traceparent, span
from argus.infrastructure.queue.queue import ClaimedJob, JobQueue
from argus.infrastructure.queue.registry import NonRetryableJobError, TaskContext, TaskRegistry

log = get_logger(__name__)


@dataclass(frozen=True)
class WorkerConfig:
    worker_id: str
    queues: tuple[str, ...]
    concurrency: int = 4
    lease_s: int = 60
    heartbeat_s: float = 15.0
    poll_interval_s: float = 2.0
    shutdown_grace_s: float = 30.0


def _describe(exc: BaseException) -> str:
    message = redact_text(str(exc))[:500]
    return f"{type(exc).__name__}: {message}" if message else type(exc).__name__


class Worker:
    def __init__(
        self,
        *,
        queue: JobQueue,
        registry: TaskRegistry,
        services: Any,
        config: WorkerConfig,
        metrics: Metrics | None = None,
    ) -> None:
        self._queue = queue
        self._registry = registry
        self._services = services
        self._config = config
        self._metrics = metrics
        self._wake = asyncio.Event()
        self._running: set[asyncio.Task[None]] = set()

    def wake(self) -> None:
        """Called by the LISTEN/NOTIFY listener when new work arrives."""
        self._wake.set()

    # ------------------------------------------------------------------- main loop
    async def run(self, stop: asyncio.Event) -> None:
        log.info(
            "worker.started", worker_id=self._config.worker_id, queues=list(self._config.queues)
        )
        slot_freed = asyncio.Event()
        while not stop.is_set():
            free = self._config.concurrency - len(self._running)
            if free > 0:
                try:
                    jobs = await self._queue.claim(
                        worker_id=self._config.worker_id,
                        queues=self._config.queues,
                        limit=free,
                        lease_s=self._config.lease_s,
                    )
                except Exception as exc:  # noqa: BLE001 - database blips must not kill the worker
                    log.warning("worker.claim_failed", error=_describe(exc))
                    jobs = []
                for job in jobs:
                    task = asyncio.create_task(self._execute(job))
                    self._running.add(task)
                    task.add_done_callback(self._running.discard)
                    task.add_done_callback(lambda _: slot_freed.set())
                if jobs and len(jobs) == free:
                    continue  # saturated: loop again as soon as a slot frees up
            waiters = [
                asyncio.create_task(self._wake.wait()),
                asyncio.create_task(stop.wait()),
                asyncio.create_task(slot_freed.wait()),
            ]
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(self._config.poll_interval_s):
                    await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
            for waiter in waiters:
                waiter.cancel()
            self._wake.clear()
            slot_freed.clear()
        await self._drain()
        log.info("worker.stopped", worker_id=self._config.worker_id)

    async def _drain(self) -> None:
        if not self._running:
            return
        _, pending = await asyncio.wait(set(self._running), timeout=self._config.shutdown_grace_s)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    async def run_until_idle(self, *, max_rounds: int = 100) -> int:
        """Test/CLI helper: process jobs until none is immediately claimable."""
        processed = 0
        for _ in range(max_rounds):
            jobs = await self._queue.claim(
                worker_id=self._config.worker_id,
                queues=self._config.queues,
                limit=self._config.concurrency,
                lease_s=self._config.lease_s,
            )
            if not jobs:
                break
            await asyncio.gather(*(self._execute(job) for job in jobs))
            processed += len(jobs)
        return processed

    # --------------------------------------------------------------- one job
    async def _execute(self, job: ClaimedJob) -> None:
        with span(
            f"job {job.task}",
            kind=SpanKind.CONSUMER,
            parent=context_from_traceparent(job.trace_parent),
            attributes={
                "messaging.system": "postgresql",
                "messaging.destination.name": job.queue,
                "argus.job.id": job.id,
                "argus.job.task": job.task,
                "argus.job.attempt": job.attempt,
                "argus.organization.id": job.organization_id,
            },
        ):
            await self._execute_in_span(job)

    async def _execute_in_span(self, job: ClaimedJob) -> None:
        started = time.perf_counter()
        outcome = "succeeded"
        with context.bind(
            job_id=job.id, organization_id=job.organization_id, worker_id=job.worker_id
        ):
            definition = self._registry.get(job.task)
            if definition is None:
                await self._queue.fail(job, f"unknown task {job.task!r}", retry=False)
                self._record(job, "failed", started)
                return
            try:
                payload = definition.payload_model.model_validate(job.payload)
            except ValidationError:
                await self._queue.fail(job, "invalid payload", retry=False)
                self._record(job, "failed", started)
                return

            lease_lost = asyncio.Event()
            ctx = TaskContext(
                job_id=job.id,
                attempt=job.attempt,
                max_attempts=job.max_attempts,
                organization_id=job.organization_id,
                services=self._services,
                cancelled=lease_lost.is_set,
            )
            handler: asyncio.Task[dict[str, Any] | None] = asyncio.ensure_future(
                definition.handler(ctx, payload)
            )
            heartbeat = asyncio.create_task(self._heartbeat(job, handler, lease_lost))
            try:
                async with asyncio.timeout(job.timeout_s):
                    result = await handler
            except TimeoutError:
                outcome = await self._failed(
                    job, "timed out", retry=definition.idempotent, definition=definition
                )
            except asyncio.CancelledError:
                if lease_lost.is_set():
                    log.warning("job.lease_lost", task=job.task)
                    self._record(job, "lease_lost", started)
                    return
                with contextlib.suppress(Exception):
                    await asyncio.shield(self._queue.release(job))
                raise
            except NonRetryableJobError as exc:
                outcome = await self._failed(
                    job, _describe(exc), retry=False, definition=definition
                )
            except Exception as exc:  # noqa: BLE001 - classified and recorded below
                log.warning("job.failed", task=job.task, attempt=job.attempt, error=_describe(exc))
                outcome = await self._failed(
                    job, _describe(exc), retry=definition.idempotent, definition=definition
                )
            else:
                if not await self._queue.complete(job, result):
                    outcome = "fenced_out"
            finally:
                heartbeat.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await heartbeat
            self._record(job, outcome, started)

    async def _failed(self, job: ClaimedJob, error: str, *, retry: bool, definition: Any) -> str:
        backoff = definition.retry.backoff(job.attempt)
        status = await self._queue.fail(job, error, retry=retry, backoff_s=backoff)
        return status or "fenced_out"

    async def _heartbeat(
        self, job: ClaimedJob, handler: asyncio.Task[Any], lease_lost: asyncio.Event
    ) -> None:
        while not handler.done():
            await asyncio.sleep(self._config.heartbeat_s)
            try:
                still_ours = await self._queue.heartbeat(job, lease_s=self._config.lease_s)
            except Exception as exc:  # noqa: BLE001 - transient; the lease still has time left
                log.warning("job.heartbeat_failed", error=_describe(exc))
                continue
            if not still_ours:
                lease_lost.set()
                handler.cancel()
                return

    def _record(self, job: ClaimedJob, outcome: str, started: float) -> None:
        trace.get_current_span().set_attribute("argus.job.outcome", outcome)
        if outcome not in {"succeeded", "lease_lost", "fenced_out"}:
            trace.get_current_span().set_status(Status(StatusCode.ERROR, outcome))
        if self._metrics is None:
            return
        self._metrics.jobs.labels(job.queue, job.task, outcome).inc()
        self._metrics.job_duration.labels(job.task).observe(time.perf_counter() - started)
