# Phase 4 - Research job system

## 1. Purpose
Research takes minutes. The API must accept a request, persist it, and hand it to background
workers reliably: no lost jobs, no duplicate jobs, no job run twice to completion, resumable after
crashes, cancellable, and pausable for human approval.

## 2. Architecture
```
POST /research-jobs ─(one transaction)─▶ research_jobs row + jobs row + idempotency record + audit
                                          └─ NOTIFY argus_jobs (delivered on commit)
worker: LISTEN ─▶ claim (FOR UPDATE SKIP LOCKED, lease, attempt+1) ─▶ handler under deadline
        heartbeat extends lease; fenced complete/fail; retries with full-jitter backoff; DLQ
scheduler (advisory-lock leader): reap expired leases, queue metrics, sweeps
pipeline: stage → checkpoint (research_steps) → stage → ... ; cancel / approval / budget aware
```

## 3. Why PostgreSQL as the queue
Creating the job and enqueueing it must be atomic (ADR 0003). The queue table, `SKIP LOCKED`,
advisory locks and `LISTEN/NOTIFY` give leases, fan-out and push wake-ups without new infrastructure.

## 4. Security and correctness considerations
* **Fencing** - every post-claim update matches `(id, status=running, locked_by, attempts)`; a
  worker whose lease expired cannot overwrite the new owner's result (tested).
* **Idempotency** - stored in the same transaction as the job; different body + same key → 422.
* **Non-idempotent tasks** get one attempt (enforced at registration).
* **Errors stored redacted** - `jobs.last_error` passes through the redaction filter (tested with a
  password in an exception message).
* **Payload validation** - malformed payloads fail permanently instead of retrying forever.
* **Payloads carry ids only**, never document text or prompts, so the infrastructure table needs no
  tenant RLS; the worker re-enters the tenant context from the job's organisation id.
* **Approvals** - a stage can park a job until an authorised human decides; strict booleans
  (`{"approve": 1}` is rejected).

## 5. Files
`infrastructure/queue/{models,queue,registry,worker,scheduler}.py`, `infrastructure/idempotency.py`,
`modules/research/{models,schemas,service,pipeline,tasks}.py`, `apps/worker/main.py`,
`apps/scheduler/main.py`, `apps/api/v1/research.py`, `migrations/versions/0004_jobs_and_research.py`.

## 6. Code worth reading
* `queue.py` - the five SQL statements are the whole protocol; read `_CLAIM` and `_FAIL`.
* `worker.py::_execute` - deadline, heartbeat, lease-loss cancellation, graceful release.
* `pipeline.py::run` - how control-flow exceptions (cancel, approval, budget, permanent failure)
  map to job states, and why stage failures on the final attempt mark the job failed.

## 7. Tests
`tests/integration/test_queue.py` (transactional enqueue, NOTIFY only on commit, concurrent
claims, fencing, reaping, DLQ + requeue, retry/backoff, timeouts, lease loss, graceful
shutdown, leader election) and `tests/integration/test_research_jobs.py` (API → queue → pipeline,
idempotency replay/conflict, checkpoint resume, budgets, cancellation, approvals, tenant
isolation, request validation).

## 8. Common mistakes avoided
Redis queues with a separate DB commit (dual write); retrying everything; trusting a worker's late
result; `OFFSET` pagination for job lists; long transactions held while a job runs (each stage
transition is its own short transaction).

## 9. Scalability
Workers scale horizontally (claims never block each other); the claim index is partial on
`status = 'queued'`; leader election needs no extra service; queue depth is exported for
autoscaling.

## 10. Next phases
Stages arrive in phases 5-15 (collect, process, retrieve, plan, analyse, verify, report). The
engine does not change.

## 11. Acceptance criteria
- [x] Double submission with one key → one job; changed body → 422.
- [x] A job whose worker froze is reaped, re-claimed, and the stale worker is fenced out.
- [x] Retries back off; exhausted jobs are dead-lettered and can be re-queued.
- [x] A crashed stage resumes from its checkpoint; earlier stages are not re-run.
- [x] Cancel works for queued (immediate) and running (cooperative) jobs; approvals gate stages.
