# Alert runbooks

Each alert in [`deploy/observability/prometheus/rules/argus-alerts.yml`](../../deploy/observability/prometheus/rules/argus-alerts.yml)
links here. Every section answers three questions: what it means, how to confirm it, what to do.
Traces (Jaeger/Tempo) are searched by `argus.request_id` (the `X-Request-ID` response header),
`argus.job.id` or `argus.organization.id`; log lines carry the same `trace_id`.

## Availability

### ArgusTargetDown
**Meaning**: Prometheus cannot scrape an API, worker or scheduler instance.
**Confirm**: `kubectl get pods` / `docker compose ps`; the process logs; for workers and the
scheduler, `ARGUS_OBSERVABILITY__METRICS_PORT` must be set or there is nothing to scrape.
**Act**: restart the instance; if it crash-loops, the first log lines usually name the
configuration problem (production refuses insecure settings at start-up on purpose).

### ArgusHighErrorRate
**Meaning**: more than 2% of API requests end in a 5xx.
**Confirm**: the `argus_http_requests_total` panel by route; error traces (status `ERROR`); logs
with `request.unhandled_exception`.
**Act**: if one route: roll back the last release touching it. If all routes: check PostgreSQL
(`/health/ready`), Redis and recent migrations.

### ArgusSlowRequests
**Meaning**: API p95 latency above one second (uploads and exports excluded).
**Confirm**: latency by route; the slowest traces show which child span (database statement,
model call, fetch) takes the time.
**Act**: database spans → see ArgusDatabaseSlow; model spans → provider latency (the gateway's
fallbacks); otherwise scale API replicas.

### ArgusDatabaseSlow
**Meaning**: database statements p95 above 500 ms.
**Confirm**: `db SELECT`/`db UPDATE` spans with the longest durations carry the statement text
(parameterised, no values); `pg_stat_statements`; lock waits (`pg_locks`).
**Act**: `EXPLAIN (ANALYZE, BUFFERS)` the statement; missing index → a migration; lock
contention → find the long transaction (statement and lock timeouts bound every connection).

### ArgusDatabasePoolSaturated
**Meaning**: a process has more than 90% of its connections (`pool_size + max_overflow`) checked
out for ten minutes; the next requests wait up to `ARGUS_DATABASE__POOL_TIMEOUT_S` and then fail.
**Confirm**: `argus_db_pool_connections` by state per instance; long transactions in
`pg_stat_activity`; worker concurrency × `ARGUS_EGRESS__MAX_CONCURRENT_FETCHES`.
**Act**: find slow statements first (ArgusDatabaseSlow). Raising the pool is safe only while
the sum over all processes stays below PostgreSQL's `max_connections` minus a reserve; beyond
that, put PgBouncer (transaction mode) in front - the per-transaction tenant context makes that
safe.

## Work

### ArgusQueueBacklog
**Meaning**: more than 500 jobs waiting in one queue for 15 minutes.
**Confirm**: `argus_queue_depth` by queue; `argus_jobs_total` rate (are workers completing
anything?); dead workers (ArgusTargetDown).
**Act**: scale workers for that queue (`ARGUS_WORKER__QUEUES` lets a deployment serve only some
queues); if jobs are stuck, look for a downstream outage (provider, search API).

### ArgusJobsDeadLettered
**Meaning**: jobs exhausted their retries.
**Confirm**: `argus jobs dead` (CLI) lists dead-lettered and failed jobs with the redacted last error.
**Act**: fix the cause, then `argus jobs requeue <id>`. Every current task is declared idempotent
(the registry refuses retries for any that is not), so running one again is safe.

### ArgusJobFailureRate
**Meaning**: more than 10% of jobs fail.
**Confirm**: `argus_jobs_total{outcome}` by task; failed job spans (`argus.job.outcome`).
**Act**: as ArgusJobsDeadLettered; a single task failing usually points to its dependency.

### ArgusSchedulerTaskFailing
**Meaning**: a periodic duty (lease reaping, monitor dispatch, audit verification...) fails
repeatedly.
**Confirm**: scheduler logs `scheduler.task_failed` with the task name; its spans.
**Act**: most duties are safe to retry; audit verification failing means integrity is not
being checked - treat it as urgent.

## AI

### ArgusLLMProviderErrors
**Meaning**: more than 20% of calls to a provider fail (errors, retries exhausted, breaker open).
**Confirm**: `argus_llm_requests_total{outcome}` by provider and model; the provider's status
page.
**Act**: the gateway already falls back; if quality or cost suffers, pin a route in the routing
file or engage a `provider` kill switch to stop using it deliberately.

### ArgusLLMCostSpike
**Meaning**: model spend in the last hour is more than three times the same hour yesterday.
**Confirm**: cost by model and task; agent runs with high `argus.agent.cost_usd`; per-organisation
usage (`llm_usage_daily`).
**Act**: budgets stop runaway jobs per job and per organisation; if one organisation or agent is
responsible, use a kill switch while investigating.

### ArgusRetrievalEmpty
**Meaning**: more than half of knowledge searches return nothing for an hour.
**Confirm**: `argus_knowledge_retrieval_results` distribution; indexing (`argus_knowledge_chunks_indexed_total`);
embedding provider errors; a recently changed embedding model (vectors of another model are not
comparable).
**Act**: re-index after an embedding change; fix the provider; check the reranker configuration.

## Security

### ArgusAuditChainBroken
**Meaning**: an organisation's audit chain failed verification: rows were edited, deleted or
forged outside the application.
**Confirm**: the organisation's security centre (`/security/audit-verifications`) names the first
broken event and the reason; `argus audit verify` (owner role) checks every chain.
**Act**: incident. Do not modify or restore the database; take a snapshot; compare with backups
to find what changed; rotate database credentials; review who had superuser access.

### ArgusAgentToolDenials
**Meaning**: an agent asked for a tool outside its allow-list.
**Confirm**: `agent.tool_denied` audit events and the agent run's `tool_calls` rows; the evidence
the agent read in that run (injection flags).
**Act**: nothing ran - the runtime refused. Find the injected source, block its domain, and keep
the run for the evaluation dataset.

### ArgusInjectionSurge
**Meaning**: many high-risk prompt-injection detections in an hour.
**Confirm**: sources and documents with `injection_level = high`; which organisations and
domains.
**Act**: high-risk content is already kept out of model context; block the domains, inform the
affected organisations.

### ArgusEgressBlockedSurge
**Meaning**: many outbound requests blocked by the SSRF guard.
**Confirm**: `argus_egress_blocked_total{reason}`; sources with status `blocked`; monitors
created recently.
**Act**: an organisation trying internal addresses is probing: review its monitors and sources,
suspend the account if deliberate.

### ArgusAccessDeniedSurge
**Meaning**: members are refused many actions.
**Confirm**: the organisation's security events (`access.denied` with route and permission).
**Act**: a broken client after a role change → fix the role; systematic probing of permissions →
suspend the member and review their sessions and keys.

### ArgusLoginFailureSurge
**Meaning**: many failed sign-ins in 15 minutes.
**Confirm**: `auth.login.failed` events in the platform audit chain; source addresses.
**Act**: per-IP and per-account limits and lockouts are already active; block the source ranges at
the edge if the volume continues.

### ArgusRateLimitDegraded
**Meaning**: Redis is unreachable, so rate limits fall back to per-process counters.
**Confirm**: Redis health; `ratelimit.degraded` warnings.
**Act**: restore Redis. Until then every replica applies limits on its own (a client can get
replicas × the limit).
