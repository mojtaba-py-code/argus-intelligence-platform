# ADR 0003 - Durable job queue in PostgreSQL

**Context.** Research jobs run for minutes. The API must create the job record and schedule the
work atomically. With a Redis-based queue (Celery, RQ, arq) the database commit and the enqueue are
two writes to two systems: either can succeed alone (the dual-write problem), producing jobs that
never run, or workers that cannot find their job.

**Decision.** A `jobs` table is the queue. Producers insert in the same transaction as the business
row and issue `NOTIFY` (delivered only on commit). Workers claim with
`UPDATE ... WHERE id IN (SELECT ... FOR UPDATE SKIP LOCKED)`, receive a **lease** (`locked_until`)
that a heartbeat extends, and a fencing value (`attempts`) that makes a late write from an expired
worker detectable and rejected. Failures are retried with exponential backoff and full jitter; after
`max_attempts` the job moves to the dead-letter state (`dead`) where it can be inspected and
re-queued. Handlers declare whether they are idempotent; non-idempotent handlers are never retried
automatically.

**Consequences.** Exactly-once *creation*, at-least-once *execution* with checkpointed, idempotent
steps. Throughput is bounded by PostgreSQL (thousands of jobs per second with the right indexes -
far above what a research platform needs). The queue is inspectable with SQL.

**Rejected.** Celery + Redis (dual write; Redis becomes a source of truth), Kafka (operational
weight, no per-message leases), a managed cloud queue (lock-in for no benefit here).
