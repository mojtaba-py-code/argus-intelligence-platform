# Specification Review - What Changed and Why

The master specification invited improvements wherever another approach is objectively better.
These are the deliberate deviations. Each one keeps the specification's intent and makes the
system safer, simpler or more correct.

| # | Specification said | Implemented instead | Why |
|---|---|---|---|
| 1 | Top-level `apps/ services/ domain/ infrastructure/` | One `src/argus` package with bounded-context modules and import-linter contracts | See [repository-structure.md](architecture/repository-structure.md): vertical slices, enforced boundaries, `src` layout. |
| 2 | Queue (implicitly Redis/Celery-style) + Redis for "job coordination" | Durable queue **in PostgreSQL** (`SKIP LOCKED` leases, fencing, `LISTEN/NOTIFY`) | Creating a job and enqueueing it must be one transaction; Redis-based queues cannot give that (dual-write problem). Redis stays a cache and rate limiter, never a source of truth - which is the specification's own rule in §20. |
| 3 | Redis for sessions | Sessions in PostgreSQL, revocation state cached in Redis | Sessions are security state and must survive a Redis flush. |
| 4 | `roles` and `permissions` tables | Permission catalogue and role matrix **in code** (versioned, reviewed, tested); the database stores assignments only | A database-editable permission catalogue is a privilege-escalation surface. Custom per-organisation roles can be added later on top of the same policy engine. |
| 5 | `query_database()` tool for agents | `query_knowledge()` with typed filters | An LLM must never author SQL. The tool covers the same need (look up entities, relations, findings) through parameterised queries inside the tenant scope. |
| 6 | `analyze_data()` with a sandbox for generated code (§17) | Declarative, non-Turing-complete analysis operations (filter, group, aggregate, sort, top-k) | Most research analysis needs aggregation, not arbitrary code. In-process Python "sandboxes" are not sandboxes. A real code sandbox (gVisor/Firecracker service) fits behind the same interface later; it is disabled by default. |
| 7 | Docker + CI/CD in phase 22 | CI and Docker from phase 1; phase 22 *hardens* them (SBOM, signing, image scanning) | Quality gates are only useful if they run from the first commit. |
| 8 | Observability in phase 20 | Structured logs, request ids and redaction from phase 1; tracing and metrics dashboards in phase 20 | Debugging phases 2-19 without logs would be guesswork. |
| 9 | Security Agent analyses prompt injection | Deterministic heuristic classifier is the always-on first layer; the LLM classifier is an optional second opinion that can only *raise* risk | LLM classifiers are themselves injectable; a control that an attacker can talk out of its decision cannot be the only control. |
| 10 | Monitoring tracks "new employees" | Organisational signals only (job postings count, team pages), no tracking of named individuals | Privacy by design (§41): monitoring identifiable people's employment changes is personal-data processing the platform has no need for. |
| 11 | robots.txt "where appropriate" | robots.txt **respected by default**; organisations can only make the policy stricter | Being a good citizen of the web is part of "production-grade"; ignoring robots.txt invites blocking and legal risk. |
| 12 | Indirect injection via "emails" | Red-team corpus covers web pages, PDFs, DOCX, search results, stored findings and tool output | The platform does not ingest e-mail; the categories it does ingest are covered. |
| 13 | JWT (unspecified algorithm) | EdDSA access tokens + **opaque** rotating refresh tokens with reuse detection | Asymmetric signing and revocable refresh tokens; see ADR 0005. |
| 14 | Idempotency (store unspecified) | Idempotency records in PostgreSQL, written in the same transaction as the job | A Redis idempotency key can say "done" for a job whose transaction rolled back. |
| 15 | Knowledge graph (unspecified store) | PostgreSQL adjacency tables + recursive CTEs | Same transactional store, same RLS; a graph database can be added when traversal depth or volume demands it. |
| 16 | Vector DB "or pgvector initially" | pgvector with authorisation in the same SQL statement | Deletion guarantees and tenant filtering are single-system properties; see ADR 0004. |
| 17 | "Never send sensitive data to an external LLM unless policy permits" | Every content part carries a classification; the gateway enforces `allowed / restricted / never` per provider locality before any network call; a local provider exists | Turns a guideline into an enforced, testable control. |
| 18 | Password reset / verification tokens (format unspecified) | 256-bit random, stored hashed, single use, short expiry, attempt-limited MFA challenges | Tokens in a database dump must be useless. |

## Open decisions for the product owner

* **Default model mix and budgets** - defaults favour quality (`claude-opus-5-5` for reasoning
  tasks). Organisations can lower cost through routing configuration and monthly budgets.
* **Search provider** - Brave Search API and self-hosted SearXNG adapters are included; which one
  production uses is a commercial choice (cost, terms of service).
* **Malware scanning** - the ClamAV adapter is included; production may prefer a managed scanner.
