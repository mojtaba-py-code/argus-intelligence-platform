"""Phase 4: the durable queue, the worker runner and the leader-elected scheduler."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any
from uuid import UUID

import pytest
from pydantic import BaseModel
from sqlalchemy import text

from argus.core.config import Settings
from argus.core.ids import uuid7
from argus.core.retry import RetryPolicy
from argus.infrastructure.db import Database
from argus.infrastructure.queue import (
    JobQueue,
    JobSpec,
    NonRetryableJobError,
    TaskContext,
    TaskDefinition,
    TaskRegistry,
)
from argus.infrastructure.queue.queue import NOTIFY_CHANNEL
from argus.infrastructure.queue.scheduler import LeaderLock, PeriodicScheduler, PeriodicTask
from argus.infrastructure.queue.worker import Worker, WorkerConfig

pytestmark = pytest.mark.integration


class Payload(BaseModel):
    value: int = 0


@pytest.fixture
async def db(db_settings: Settings) -> AsyncIterator[Database]:
    database = Database(db_settings.database)
    async with database.session() as session:
        await session.execute(text("DELETE FROM jobs"))
    yield database
    await database.dispose()


def _worker(queue: JobQueue, registry: TaskRegistry, **config: Any) -> Worker:
    return Worker(
        queue=queue,
        registry=registry,
        services=None,
        config=WorkerConfig(
            worker_id=config.pop("worker_id", f"w-{uuid7().hex[:6]}"),
            queues=("default",),
            concurrency=config.pop("concurrency", 2),
            lease_s=config.pop("lease_s", 30),
            heartbeat_s=config.pop("heartbeat_s", 5),
            poll_interval_s=0.05,
            shutdown_grace_s=config.pop("shutdown_grace_s", 1),
        ),
    )


async def _status(db: Database, job_id: UUID) -> dict[str, Any]:
    async with db.session() as session:
        row = (
            (
                await session.execute(
                    text(
                        "SELECT status, attempts, last_error, run_at > now() AS delayed, result FROM jobs WHERE id = :id"
                    ),
                    {"id": job_id},
                )
            )
            .mappings()
            .one()
        )
    return dict(row)


async def _release_delays(db: Database) -> None:
    async with db.session() as session:
        await session.execute(text("UPDATE jobs SET run_at = now() WHERE status = 'queued'"))


async def _enqueue_then_roll_back(db: Database, queue: JobQueue, spec: JobSpec) -> None:
    async with db.session() as session:
        await queue.enqueue(session, spec)
        raise RuntimeError("rollback")


# ------------------------------------------------------------------------------ enqueue
async def test_enqueue_is_transactional(db: Database) -> None:
    queue = JobQueue(db)
    with pytest.raises(RuntimeError, match="rollback"):
        await _enqueue_then_roll_back(db, queue, JobSpec(task="t"))
    assert await queue.depth() == {}
    async with db.session() as session:
        job_id = await queue.enqueue(session, JobSpec(task="t"))
    assert (await _status(db, job_id))["status"] == "queued"


async def test_dedup_key_returns_the_active_job(db: Database) -> None:
    queue = JobQueue(db)
    first = await queue.enqueue_now(JobSpec(task="t", dedup_key="k-1"))
    second = await queue.enqueue_now(JobSpec(task="t", dedup_key="k-1"))
    assert first == second
    assert (await queue.depth())["default"] == 1


async def test_notify_is_delivered_only_on_commit(db: Database) -> None:
    queue = JobQueue(db)
    received: list[str] = []
    listener = await db.connect_raw("test-listen")
    try:
        await listener.add_listener(NOTIFY_CHANNEL, lambda *args: received.append(args[-1]))
        with pytest.raises(RuntimeError, match="rollback"):
            await _enqueue_then_roll_back(db, queue, JobSpec(task="t", queue="research"))
        await asyncio.sleep(0.2)
        assert received == []
        await queue.enqueue_now(JobSpec(task="t", queue="research"))
        for _ in range(50):
            if received:
                break
            await asyncio.sleep(0.05)
        assert received == ["research"]
    finally:
        await listener.close()


# -------------------------------------------------------------------------------- claim
async def test_concurrent_claims_never_share_a_job(db: Database) -> None:
    queue = JobQueue(db)
    for _ in range(10):
        await queue.enqueue_now(JobSpec(task="t"))
    batches = await asyncio.gather(
        *(
            queue.claim(worker_id=f"w{i}", queues=("default",), limit=3, lease_s=30)
            for i in range(5)
        )
    )
    claimed = [job.id for batch in batches for job in batch]
    assert len(claimed) == 10
    assert len(set(claimed)) == 10


async def test_fencing_rejects_a_worker_whose_lease_expired(db: Database) -> None:
    queue = JobQueue(db)
    await queue.enqueue_now(JobSpec(task="t"))
    (stale,) = await queue.claim(worker_id="A", queues=("default",), limit=1, lease_s=30)
    async with db.session() as session:  # simulate a frozen worker
        await session.execute(text("UPDATE jobs SET locked_until = now() - interval '1 second'"))
    assert await queue.reap_expired() == [stale.id]
    (fresh,) = await queue.claim(worker_id="B", queues=("default",), limit=1, lease_s=30)
    assert fresh.id == stale.id
    assert fresh.attempt == 2
    assert await queue.complete(stale, {"from": "A"}) is False  # fenced out
    assert await queue.heartbeat(stale, lease_s=30) is False
    assert await queue.complete(fresh, {"from": "B"}) is True
    assert (await _status(db, fresh.id))["result"] == {"from": "B"}


async def test_reaper_dead_letters_after_max_attempts(db: Database) -> None:
    queue = JobQueue(db)
    job_id = await queue.enqueue_now(JobSpec(task="t", max_attempts=1))
    await queue.claim(worker_id="A", queues=("default",), limit=1, lease_s=30)
    async with db.session() as session:
        await session.execute(text("UPDATE jobs SET locked_until = now() - interval '1 second'"))
    await queue.reap_expired()
    assert (await _status(db, job_id))["status"] == "dead"
    assert [j["id"] for j in await queue.dead_letters()] == [job_id]
    assert await queue.requeue(job_id)
    assert (await _status(db, job_id))["status"] == "queued"


# ------------------------------------------------------------------------------- worker
async def test_worker_retries_with_backoff_then_dead_letters(db: Database) -> None:
    queue = JobQueue(db)
    calls: list[int] = []

    async def flaky(ctx: TaskContext, payload: Payload) -> dict[str, Any]:
        calls.append(ctx.attempt)
        raise RuntimeError("transient password=hunter2")

    registry = TaskRegistry()
    registry.register(
        TaskDefinition("flaky", flaky, Payload, max_attempts=3, retry=RetryPolicy(base_delay_s=60))
    )
    job_id = await queue.enqueue_now(JobSpec(task="flaky", max_attempts=3))
    worker = _worker(queue, registry)
    for _ in range(3):
        await worker.run_until_idle()
        status = await _status(db, job_id)
        if status["status"] == "queued":
            assert status["delayed"]  # backoff scheduled in the future
            await _release_delays(db)
    final = await _status(db, job_id)
    assert calls == [1, 2, 3]
    assert final["status"] == "dead"
    assert "hunter2" not in final["last_error"]  # errors are redacted before storage


async def test_non_retryable_errors_and_bad_payloads_fail_immediately(db: Database) -> None:
    queue = JobQueue(db)

    async def refuse(ctx: TaskContext, payload: Payload) -> None:
        raise NonRetryableJobError("resource gone")

    registry = TaskRegistry()
    registry.register(TaskDefinition("refuse", refuse, Payload))
    first = await queue.enqueue_now(JobSpec(task="refuse"))
    bad_payload = await queue.enqueue_now(JobSpec(task="refuse", payload={"value": "not-an-int"}))
    unknown = await queue.enqueue_now(JobSpec(task="does-not-exist"))
    await _worker(queue, registry).run_until_idle()
    for job_id in (first, bad_payload, unknown):
        assert (await _status(db, job_id))["status"] == "failed"


def test_non_idempotent_tasks_cannot_be_retried() -> None:
    async def send(ctx: TaskContext, payload: Payload) -> None:
        return None

    with pytest.raises(ValueError, match="non-idempotent"):
        TaskDefinition("email.send", send, Payload, idempotent=False, max_attempts=3)
    TaskDefinition("email.send", send, Payload, idempotent=False, max_attempts=1)


async def test_job_timeout_is_enforced(db: Database) -> None:
    queue = JobQueue(db)

    async def slow(ctx: TaskContext, payload: Payload) -> None:
        await asyncio.sleep(10)

    registry = TaskRegistry()
    registry.register(TaskDefinition("slow", slow, Payload, timeout_s=1, max_attempts=1))
    job_id = await queue.enqueue_now(JobSpec(task="slow", timeout_s=1, max_attempts=1))
    await _worker(queue, registry).run_until_idle()
    status = await _status(db, job_id)
    assert status["status"] == "dead"
    assert "timed out" in status["last_error"]


async def test_lost_lease_cancels_the_handler(db: Database) -> None:
    queue = JobQueue(db)
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def long(ctx: TaskContext, payload: Payload) -> None:
        started.set()
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    registry = TaskRegistry()
    registry.register(TaskDefinition("long", long, Payload, timeout_s=60))
    job_id = await queue.enqueue_now(JobSpec(task="long", timeout_s=60))
    worker = _worker(queue, registry, heartbeat_s=0.2)
    run = asyncio.create_task(worker.run_until_idle())
    await asyncio.wait_for(started.wait(), 5)
    async with db.session() as session:  # someone else took the job over
        await session.execute(
            text("UPDATE jobs SET locked_by = 'other-worker' WHERE id = :id"), {"id": job_id}
        )
    await asyncio.wait_for(cancelled.wait(), 5)
    await run
    assert (await _status(db, job_id))["status"] == "running"  # untouched: the new owner decides


async def test_graceful_shutdown_releases_unfinished_jobs(db: Database) -> None:
    queue = JobQueue(db)
    started = asyncio.Event()

    async def long(ctx: TaskContext, payload: Payload) -> None:
        started.set()
        await asyncio.sleep(30)

    registry = TaskRegistry()
    registry.register(TaskDefinition("long", long, Payload, timeout_s=60))
    job_id = await queue.enqueue_now(JobSpec(task="long", timeout_s=60))
    worker = _worker(queue, registry, shutdown_grace_s=0.2)
    stop = asyncio.Event()
    run = asyncio.create_task(worker.run(stop))
    await asyncio.wait_for(started.wait(), 5)
    stop.set()
    await asyncio.wait_for(run, 10)
    status = await _status(db, job_id)
    assert status["status"] == "queued"
    assert status["attempts"] == 0  # released, not counted as a failed attempt


async def test_worker_completes_and_records_results(db: Database) -> None:
    queue = JobQueue(db)

    async def double(ctx: TaskContext, payload: Payload) -> dict[str, Any]:
        return {"doubled": payload.value * 2}

    registry = TaskRegistry()
    registry.register(TaskDefinition("double", double, Payload))
    ids = [await queue.enqueue_now(JobSpec(task="double", payload={"value": i})) for i in range(5)]
    assert await _worker(queue, registry, concurrency=3).run_until_idle() == 5
    results = [(await _status(db, job_id))["result"] for job_id in ids]
    assert results == [{"doubled": i * 2} for i in range(5)]


# ---------------------------------------------------------------------------- scheduler
async def test_only_one_scheduler_is_leader(db: Database) -> None:
    first, second = LeaderLock(db, key=4242), LeaderLock(db, key=4242)
    try:
        assert await first.try_acquire()
        assert not await second.try_acquire()
        await first.release()
        assert await second.try_acquire()
        assert await second.verify()
    finally:
        await first.release()
        await second.release()


async def test_periodic_tasks_run_when_due_and_fail_independently() -> None:
    ran: list[str] = []

    async def ok() -> None:
        ran.append("ok")

    async def broken() -> None:
        raise RuntimeError("boom")

    scheduler = PeriodicScheduler(
        [PeriodicTask("broken", 60, broken), PeriodicTask("ok", 60, ok)],
        leader=LeaderLock(Database.__new__(Database)),
    )
    assert await scheduler.run_due() == ["ok"]
    assert await scheduler.run_due() == []  # not due again yet
    assert ran == ["ok"]
