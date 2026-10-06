# Development Roadmap

Twenty-five phases, each ending in a **working, tested system**. A phase is done when its acceptance
criteria pass in CI, its threats are mitigated or explicitly accepted in the threat model, and its
learning guide in [phases/](phases/) explains what was built and why. Security is part of every
phase, not a phase of its own: phase 19 *adds* controls, it does not start them.

Status legend: ✅ done · 🔄 in progress · ⏳ planned · ⏭ skipped by decision

| # | Phase | Status | Guide |
|---|---|---|---|
| 1 | Architecture, repository, development environment | ✅ | [phase-01](phases/phase-01-foundation.md) |
| 2 | Authentication and authorisation | ✅ | [phase-02](phases/phase-02-identity.md) |
| 3 | Multi-tenant core | ✅ | [phase-03](phases/phase-03-tenancy.md) |
| 4 | Research job system | ✅ | [phase-04](phases/phase-04-jobs.md) |
| 5 | Source collection | ✅ | [phase-05-06](phases/phase-05-06-web-research.md) |
| 6 | Secure web research | ✅ | [phase-05-06](phases/phase-05-06-web-research.md) |
| 7 | Document processing | ✅ | [phase-07](phases/phase-07-documents.md) |
| 8 | PostgreSQL knowledge store | ✅ | [phase-08-10](phases/phase-08-10-knowledge-rag.md) |
| 9 | Embeddings and vector search | ✅ | [phase-08-10](phases/phase-08-10-knowledge-rag.md) |
| 10 | Retrieval-augmented generation | ✅ | [phase-08-10](phases/phase-08-10-knowledge-rag.md) |
| 11 | LLM gateway | ✅ | [phase-11](phases/phase-11-llm-gateway.md) |
| 12 | Research planner agent | ✅ | [phase-12-14](phases/phase-12-14-agents.md) |
| 13 | Specialised agents | ✅ | [phase-12-14](phases/phase-12-14-agents.md) |
| 14 | Agent orchestration | ✅ | [phase-12-14](phases/phase-12-14-agents.md) |
| 15 | Evidence verification and reporting | ✅ | [phase-15](phases/phase-15-verification.md) |
| 16 | AI evaluation | ✅ | [phase-16](phases/phase-16-evaluation.md) |
| 17 | Continuous monitoring and notifications | ✅ | [phase-17](phases/phase-17-monitoring.md) |
| 18 | Knowledge graph | ⏭ | - (see below) |
| 19 | Advanced security | ✅ | [phase-19](phases/phase-19-advanced-security.md) |
| 20 | Observability | ✅ | [phase-20](phases/phase-20-observability.md) |
| 21 | Performance and scalability | ✅ | [phase-21](phases/phase-21-performance.md) |
| 22 | Docker and CI/CD hardening | ✅ | [phase-22](phases/phase-22-delivery.md) |
| 23 | Production deployment | ✅ | [phase-23](phases/phase-23-deployment.md) |
| 24 | SaaS architecture | ✅ | [phase-24](phases/phase-24-saas.md) |
| 25 | Final security hardening | ✅ | [phase-25](phases/phase-25-hardening.md) |

## Phase details

### Phase 1 - Architecture, repository, development environment
* **Objective**: a runnable, observable, secure-by-default skeleton every later phase builds on.
* **Components**: typed settings with production guards; structured logging with redaction;
  error model (RFC 9457); request context (request id, client IP via trusted proxies); security
  headers; body-size and timeout middleware; health/readiness; async database engine and unit of
  work; Redis client; Alembic baseline (extensions, roles' grants, RLS helper functions); CLI;
  Dockerfile, Compose, CI, pre-commit.
* **Database**: extensions `vector`, `pgcrypto`; functions `argus_current_org()`,
  `argus_current_user()`.
* **Security**: production refuses insecure configuration; no stack traces to clients; secrets as
  `SecretStr`; non-root container.
* **Acceptance**: `pytest`, `ruff`, `mypy --strict`, `lint-imports` green; `/health/live` and
  `/health/ready` work; an unhandled exception yields a problem document without internals; an
  oversized body yields 413 even when chunked.

### Phase 2 - Authentication and authorisation
* **Components**: registration, e-mail verification, login, logout, refresh rotation with reuse
  detection, sessions and devices, password change/reset, TOTP MFA with recovery codes, account
  lockout, permission catalogue and role matrix, policy engine, audit log with HMAC chain.
* **Database**: `users`, `user_sessions`, `refresh_tokens`, `one_time_tokens`, `mfa_totp`,
  `mfa_recovery_codes`, `audit_logs`, `audit_chain_heads`.
* **Threats**: A1-A9, X1. **Acceptance**: replayed refresh token revokes the session; no response
  or timing difference between unknown and known e-mails beyond noise; audit chain verifies.

### Phase 3 - Multi-tenant core
* **Components**: organisations, memberships, invitations, projects (organisation/restricted),
  project members, service accounts, API keys with scopes, tenant scope + RLS unit of work.
* **Database**: `organizations`, `organization_members`, `invitations`, `projects`,
  `project_members`, `service_accounts`, `api_keys`; RLS on all tenant tables; composite FKs.
* **Threats**: T1-T5, A8. **Acceptance**: the tenant-isolation suite (as the runtime role, raw SQL
  included) proves zero cross-tenant reads/writes; foreign ids return 404.

### Phase 4 - Research job system
* **Components**: PostgreSQL job queue (leases, heartbeats, fencing, backoff, dead letters,
  LISTEN/NOTIFY), worker process, scheduler with leader election, research jobs with stages and
  progress, cancellation, idempotency keys, approvals.
* **Database**: `jobs`, `idempotency_keys`, `research_jobs`, `research_plans`, `research_steps`,
  `approval_requests`.
* **Threats**: X4, P6. **Acceptance**: double submission with one key creates one job; a killed
  worker's job is resumed by another; a job exceeding `max_attempts` is dead-lettered.

### Phases 5-6 - Source collection and secure web research
* **Components**: SSRF guard and pinned egress backend, safe fetcher (redirects, caps, bounded
  decompression, content-type policy), robots.txt cache, politeness, HTML extraction with hidden
  text removal, Unicode sanitisation, search providers (Brave, SearXNG, static), source registry,
  reputation, domain policies.
* **Database**: `sources`, `source_snapshots`, `domain_policies`.
* **Threats**: W1-W7. **Acceptance**: the SSRF corpus (decimal/octal/hex IPs, IPv6 forms,
  rebinding, redirects) is blocked; property tests find no public/private misclassification.

### Phase 7 - Document processing
* **Components**: upload API with streaming size cap, magic-byte sniffing, PDF/DOCX/TXT/CSV/JSON/
  HTML/Markdown parsers in a subprocess sandbox, ZIP bomb checks, malware-scan port, quarantine,
  encrypted object storage, signed download URLs.
* **Database**: `documents`. **Threats**: D1-D5.
* **Acceptance**: polyglot, zip-bomb, XXE and EICAR fixtures are rejected; deleting a document
  removes chunks and vectors in the same transaction.

### Phases 8-10 - Knowledge store, embeddings, RAG
* **Components**: chunking, embedding providers, `document_chunks` with HNSW and GIN indexes,
  hybrid retrieval with RRF in one SQL statement, authorised scope, reranking, context packer,
  retrieval cache with corpus versioning.
* **Database**: `document_chunks`. **Acceptance**: retrieval never returns another tenant's or a
  restricted project's chunk; hybrid search beats either single method on the evaluation corpus.

### Phase 11 - LLM gateway
* **Components**: providers (Claude, OpenAI-compatible, local extractive), routing, fallback,
  retries, circuit breakers, budgets, governance, redaction, usage ledger, prompt registry and
  deployments.
* **Database**: `llm_requests`, `llm_usage_daily`, `prompt_deployments`. **Threats**: P6-P8.

### Phases 12-14 - Planner, specialised agents, orchestration
* **Components**: `AgentSpec` and the agent runtime (limits, kill switches, audited tool
  mediation), the declared tool catalogue, the planner and analyst agents with offline handlers,
  the plan → collect → analyse pipeline with cost-threshold, crawl-scope and data-policy
  approvals, creator re-authorisation at every stage, and the per-viewer results API. Design change from the original plan: web search
  and fetching are deterministic code driven by the plan, not agent tools - the only tool an agent
  holds is `search_documents` (read-only). `query_knowledge`, `analyze_data` and
  `compare_sources` are deferred to the phases that need them (15, 18).
* **Database**: `agent_runs`, `tool_calls`, `kill_switches`, `research_findings`,
  `research_citations`. **Threats**: P1-P3, P5, P6, P9, P10.

### Phase 15 - Evidence verification and reporting
* **Components**: mechanical + entailment verification (figures must appear in the evidence;
  models can only lower a verdict), contradiction candidates, judgement and verified
  justification, reporter and critic agents with code-side grounding checks and one revision,
  the canonical `argus.report/1` document with provenance and methodology, exporters (Markdown,
  JSON, CSV, PDF) that are inert, audited, rate-limited and permissioned.
* **Database**: `research_findings.support`, `research_contradictions`, `research_reports`.
  **Threats**: P2, P3, P5, P10.

### Phase 16 - AI evaluation
* **Components**: YAML datasets with a corpus web, a runner that drives the public API
  in-process, metrics recomputed from stored data (all spec §27 dimensions), a baseline gate with
  zero tolerance for security metrics, `argus eval run [--live]`, the red-team suite with a
  worst-case obedient model, and a manual live-model workflow. The first run found and fixed two
  injection weaknesses (line-wrapped instructions; injected text quoted back as a fact).

### Phase 17 - Continuous monitoring and notifications
* **Components**: URL and search monitors, per-target snapshot pointers, noise-filtered diffing,
  code significance refined by a monitoring agent, alerts, in-app and e-mail notifications,
  research job and approval events, scheduler dispatch through a narrow SECURITY DEFINER
  function. Outbound webhooks were left out of this phase by decision.
* **Database**: `monitors`, `monitor_targets`, `monitor_changes`, `notifications`.

### Phase 18 - Knowledge graph (skipped)
* **Decision (2026-10-05)**: not built. The project owner chose to continue with phases 19-25.
  Nothing in later phases depends on it: findings, citations, contradictions and reports carry
  their own provenance. The planned tables (`entities`, `entity_mentions`,
  `entity_relationships`) do not exist.

### Phase 19 - Advanced security
* **Components**: scheduled per-organisation audit-chain verification (snapshot reads, genesis
  anchored, streaming) with history and once-per-break alerts; kill-switch administration for
  organisation administrators (platform switches read-only, never via API keys); security summary
  with deterministic recommendations; security events feed; audited permission denials with a
  per-principal budget; revoked-key use attributed to its organisation; the OpenAPI-driven API
  surface security suite. Session-anomaly signals were left out by decision; key-format secret
  scanning already existed (`.github/gitleaks.toml`).
* **Database**: `audit_verifications`, `argus_audit_verification_due()`, time indexes on
  `agent_runs` and `tool_calls`. **Threats**: X1, X9-X11, A8.

### Phase 20 - Observability
* **Components**: OpenTelemetry tracing with explicit, allow-listed instrumentation (server,
  job, stage, agent, model, tool, retrieval, egress and database spans; trace context carried
  through `jobs.trace_parent`; log correlation); FastAPI native telemetry disabled; `/metrics`
  for worker and scheduler processes; every defined metric recorded; alert rules with runbooks,
  a generated Grafana dashboard, collector configuration and a local stack
  (`deploy/observability/`), all checked against the code by tests.
* **Database**: `jobs.trace_parent`. **Threats**: X12, X13.

### Phase 21 - Performance and scalability
* **Components**: benchmarks with budgets (`pytest -m perf`), a plan check over every statement
  the platform issues on growing tables, pool and statement metrics, a read-only load-test
  script; fixes driven by the measurements (keyword ranking 5x faster, one authorisation
  transaction per project request, bounded concurrent source collection, cheaper statement
  spans); capacity rules for connections, workers, vector and keyword search.

### Phase 22 - Docker and CI/CD hardening
* **Components**: release workflow (full CI on the tag, multi-arch build with SBOM and SLSA
  provenance, Trivy on the pushed digest, cosign keyless signing verified against the workflow
  identity), CI validation of compose, Prometheus and collector configuration with the real
  tools, weekly benchmarks, OCI labels, Dependabot for the observability images, and the
  delivery policy tests.

### Phase 23 - Production deployment
* **Components**: Kustomize base and overlays (restricted pod security, default-deny network
  policies that exclude internal ranges from internet egress, HPAs, PDBs, migration Job and
  audit-verification CronJob as the only holders of owner credentials), zero-downtime readiness
  across schema versions, workers waiting for the schema, `argus users disable|enable` and
  `argus audit export`, and the deployment, backup/restore, incident-response and
  disaster-recovery runbooks with RPO/RTO.

### Phase 24 - SaaS architecture
* **Components**: a plan catalogue in code (free, team, business, enterprise) with quotas
  enforced inside the creating transaction under per-organisation locks, a usage report and a
  plan-capped model budget; retention of every organisation's settings (superseded page
  versions, monitor changes, model-call rows, expired exports, finished jobs, and audit events
  behind signed checkpoints the database enforces); the organisation lifecycle (suspend, resume,
  delete with a 30-day grace period, restore, purge) with `argus orgs`; owner-only data exports;
  the dashboard API; and the **web dashboard** at `/app` (spec §53: research projects, active
  jobs, reports, sources, knowledge base, monitoring, alerts, AI usage and costs, system health,
  security events) under a Content-Security-Policy with Trusted Types. `scripts/seed_demo.py`
  fills a development database with a demo organisation.

### Phase 25 - Final security hardening
* **Components**: independent reviews of the SaaS layer and the web dashboard (no critical or
  high finding; every medium and low one fixed with a test that fails without the fix), the
  threat model checked threat by threat, every gate run together (tests with coverage, static
  analysis, dependency audit, migration drift), a behaviour suite for the dashboard's session
  logic, and a documentation audit kept honest by tests (links, roadmap guides, the permission
  model).
