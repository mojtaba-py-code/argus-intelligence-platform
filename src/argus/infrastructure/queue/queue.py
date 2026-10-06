"""Queue operations. Every state transition after ``claim`` is **fenced**: it only applies when
the row is still ``running`` under the same worker id *and* the same attempt number, so a worker
whose lease expired (and whose job was re-claimed elsewhere) can never overwrite the new owner's
outcome.

Time comes from PostgreSQL (``now()``): one clock for every worker and API replica.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.ids import uuid7
from argus.core.redaction import redact_text
from argus.infrastructure.db import Database
from argus.infrastructure.observability.tracing import current_traceparent

NOTIFY_CHANNEL = "argus_jobs"
_MAX_ERROR_CHARS = 2_000


@dataclass(frozen=True)
class JobSpec:
    task: str
    payload: dict[str, Any] = field(default_factory=dict)
    queue: str = "default"
    organization_id: UUID | None = None
    priority: int = 0
    delay_s: float = 0.0
    max_attempts: int = 3
    timeout_s: int = 300
    dedup_key: str | None = None


@dataclass(frozen=True)
class ClaimedJob:
    id: UUID
    queue: str
    task: str
    payload: dict[str, Any]
    organization_id: UUID | None
    attempt: int
    max_attempts: int
    timeout_s: int
    worker_id: str
    trace_parent: str | None = None


_ENQUEUE = text(
    """
    INSERT INTO jobs (id, queue, task, payload, organization_id, priority, run_at, max_attempts,
                      timeout_s, dedup_key, trace_parent, created_at, updated_at)
    VALUES (:id, :queue, :task, CAST(:payload AS jsonb), :org, :priority,
            now() + make_interval(secs => :delay), :max_attempts, :timeout_s, :dedup_key,
            :trace_parent, now(), now())
    ON CONFLICT (dedup_key) WHERE dedup_key IS NOT NULL AND status IN ('queued', 'running')
    DO NOTHING
    RETURNING id
    """
)
_FIND_ACTIVE = text(
    "SELECT id FROM jobs WHERE dedup_key = :dedup_key AND status IN ('queued', 'running')"
)
_CLAIM = text(
    """
    WITH next AS (
        SELECT id FROM jobs
        WHERE status = 'queued' AND queue = ANY(:queues) AND run_at <= now()
        ORDER BY priority DESC, run_at, id
        LIMIT :limit
        FOR UPDATE SKIP LOCKED
    )
    UPDATE jobs j
    SET status = 'running', locked_by = :worker, attempts = j.attempts + 1,
        locked_until = now() + make_interval(secs => :lease),
        started_at = coalesce(j.started_at, now()), updated_at = now()
    FROM next
    WHERE j.id = next.id
    RETURNING j.id, j.queue, j.task, j.payload, j.organization_id, j.attempts, j.max_attempts,
              j.timeout_s, j.trace_parent
    """
)
# Constant SQL fragment (no user input): composed into the statements below.
_FENCE = "id = :id AND status = 'running' AND locked_by = :worker AND attempts = :attempt"
_HEARTBEAT = text(
    f"UPDATE jobs SET locked_until = now() + make_interval(secs => :lease), updated_at = now() "  # nosec B608
    f"WHERE {_FENCE}"
)
_COMPLETE = text(
    "UPDATE jobs SET status = 'succeeded', result = CAST(:result AS jsonb), locked_by = NULL, "  # nosec B608
    f"locked_until = NULL, finished_at = now(), updated_at = now() WHERE {_FENCE}"
)
_FAIL = text(
    "UPDATE jobs SET status = CASE WHEN :retry AND attempts < max_attempts THEN 'queued' "  # nosec B608
    "WHEN :retry THEN 'dead' ELSE 'failed' END, "
    "run_at = CASE WHEN :retry AND attempts < max_attempts "
    "THEN now() + make_interval(secs => :backoff) ELSE run_at END, "
    "finished_at = CASE WHEN :retry AND attempts < max_attempts THEN NULL ELSE now() END, "
    "locked_by = NULL, locked_until = NULL, last_error = :error, updated_at = now() "
    f"WHERE {_FENCE} RETURNING status"
)
_RELEASE = text(
    "UPDATE jobs SET status = 'queued', run_at = now(), locked_by = NULL, locked_until = NULL, "  # nosec B608
    f"attempts = attempts - 1, updated_at = now() WHERE {_FENCE}"
)
_REAP = text(
    """
    UPDATE jobs SET
        status = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'queued' END,
        finished_at = CASE WHEN attempts >= max_attempts THEN now() ELSE NULL END,
        run_at = now(), locked_by = NULL, locked_until = NULL,
        last_error = 'lease expired (worker lost)', updated_at = now()
    WHERE status = 'running' AND locked_until < now()
    RETURNING id
    """
)


def _clip_error(error: str) -> str:
    return redact_text(error)[:_MAX_ERROR_CHARS]


class JobQueue:
    def __init__(self, database: Database) -> None:
        self._db = database

    async def enqueue(self, session: AsyncSession, spec: JobSpec) -> UUID:
        """Insert in the *caller's* transaction; ``NOTIFY`` is delivered only on commit."""
        job_id = (
            await session.execute(
                _ENQUEUE,
                {
                    "id": uuid7(),
                    "queue": spec.queue,
                    "task": spec.task,
                    "payload": json.dumps(spec.payload, default=str),
                    "org": spec.organization_id,
                    "priority": spec.priority,
                    "delay": float(max(0.0, spec.delay_s)),
                    "max_attempts": spec.max_attempts,
                    "timeout_s": spec.timeout_s,
                    "dedup_key": spec.dedup_key,
                    "trace_parent": current_traceparent(),
                },
            )
        ).scalar_one_or_none()
        if job_id is None:  # an identical active job already exists
            job_id = (
                await session.execute(_FIND_ACTIVE, {"dedup_key": spec.dedup_key})
            ).scalar_one()
        await session.execute(
            text("SELECT pg_notify(:c, :q)"), {"c": NOTIFY_CHANNEL, "q": spec.queue}
        )
        return UUID(str(job_id))

    async def enqueue_now(self, spec: JobSpec) -> UUID:
        async with self._db.session() as session:
            return await self.enqueue(session, spec)

    async def claim(
        self, *, worker_id: str, queues: tuple[str, ...], limit: int, lease_s: int
    ) -> list[ClaimedJob]:
        if limit <= 0:
            return []
        async with self._db.session() as session:
            rows = (
                await session.execute(
                    _CLAIM,
                    {
                        "queues": list(queues),
                        "limit": limit,
                        "worker": worker_id,
                        "lease": float(lease_s),
                    },
                )
            ).all()
        return [
            ClaimedJob(
                id=row.id,
                queue=row.queue,
                task=row.task,
                payload=dict(row.payload or {}),
                organization_id=row.organization_id,
                attempt=row.attempts,
                max_attempts=row.max_attempts,
                timeout_s=row.timeout_s,
                worker_id=worker_id,
                trace_parent=row.trace_parent,
            )
            for row in rows
        ]

    def _fence(self, job: ClaimedJob) -> dict[str, Any]:
        return {"id": job.id, "worker": job.worker_id, "attempt": job.attempt}

    async def heartbeat(self, job: ClaimedJob, *, lease_s: int) -> bool:
        async with self._db.session() as session:
            result = await session.execute(
                _HEARTBEAT, {**self._fence(job), "lease": float(lease_s)}
            )
            return bool(result.rowcount)  # type: ignore[attr-defined]

    async def complete(self, job: ClaimedJob, result: dict[str, Any] | None = None) -> bool:
        async with self._db.session() as session:
            outcome = await session.execute(
                _COMPLETE, {**self._fence(job), "result": json.dumps(result or {}, default=str)}
            )
            return bool(outcome.rowcount)  # type: ignore[attr-defined]

    async def fail(
        self, job: ClaimedJob, error: str, *, retry: bool, backoff_s: float = 0.0
    ) -> str | None:
        """Returns the new status (``queued``/``dead``/``failed``) or ``None`` if fenced out."""
        async with self._db.session() as session:
            status = (
                await session.execute(
                    _FAIL,
                    {
                        **self._fence(job),
                        "retry": retry,
                        "backoff": float(max(0.0, backoff_s)),
                        "error": _clip_error(error),
                    },
                )
            ).scalar_one_or_none()
            return None if status is None else str(status)

    async def release(self, job: ClaimedJob) -> bool:
        """Give a job back without consuming an attempt (graceful shutdown)."""
        async with self._db.session() as session:
            result = await session.execute(_RELEASE, self._fence(job))
            return bool(result.rowcount)  # type: ignore[attr-defined]

    async def reap_expired(self) -> list[UUID]:
        async with self._db.session() as session:
            return [row.id for row in (await session.execute(_REAP)).all()]

    async def cancel(self, session: AsyncSession, job_id: UUID) -> bool:
        """Cancel a job that has not started (in the caller's transaction)."""
        result = await session.execute(
            text(
                "UPDATE jobs SET status = 'cancelled', finished_at = now(), updated_at = now() "
                "WHERE id = :id AND status = 'queued'"
            ),
            {"id": job_id},
        )
        return bool(result.rowcount)  # type: ignore[attr-defined]

    async def depth(self) -> dict[str, int]:
        async with self._db.session(read_only=True) as session:
            rows = (
                await session.execute(
                    text(
                        "SELECT queue, count(*) AS n FROM jobs WHERE status = 'queued' GROUP BY queue"
                    )
                )
            ).all()
        return {row.queue: int(row.n) for row in rows}

    async def get(self, job_id: UUID) -> dict[str, Any] | None:
        async with self._db.session(read_only=True) as session:
            row = (
                (
                    await session.execute(
                        text(
                            "SELECT id, queue, task, status, attempts, max_attempts, run_at, last_error, "
                            "result, organization_id FROM jobs WHERE id = :id"
                        ),
                        {"id": job_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
        return dict(row) if row is not None else None

    async def dead_letters(self, *, limit: int = 100) -> list[dict[str, Any]]:
        async with self._db.session(read_only=True) as session:
            rows = (
                (
                    await session.execute(
                        text(
                            "SELECT id, queue, task, attempts, last_error, finished_at FROM jobs "
                            "WHERE status IN ('dead', 'failed') ORDER BY finished_at DESC LIMIT :n"
                        ),
                        {"n": limit},
                    )
                )
                .mappings()
                .all()
            )
        return [dict(row) for row in rows]

    async def requeue(self, job_id: UUID) -> bool:
        async with self._db.session() as session:
            result = await session.execute(
                text(
                    "UPDATE jobs SET status = 'queued', attempts = 0, run_at = now(), "
                    "finished_at = NULL, last_error = NULL, updated_at = now() "
                    "WHERE id = :id AND status IN ('dead', 'failed')"
                ),
                {"id": job_id},
            )
            await session.execute(text("SELECT pg_notify(:c, 'requeue')"), {"c": NOTIFY_CHANNEL})
            return bool(result.rowcount)  # type: ignore[attr-defined]

    async def now(self) -> datetime:
        async with self._db.session(read_only=True) as session:
            value: datetime = (await session.execute(text("SELECT now()"))).scalar_one()
            return value
