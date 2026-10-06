# Repository Structure

```text
.
├── src/argus/                    the single installable package
│   ├── core/                     kernel: settings, errors, ids, clock, context, logging,
│   │                             redaction, crypto, pagination, retry, circuit breaker
│   ├── infrastructure/           adapters to technology: db (engine, unit of work, RLS context),
│   │                             redis, storage, queue, email, observability
│   ├── security/                 security primitives: passwords, tokens, TOTP, API keys,
│   │                             permissions + policy engine, rate limiting, SSRF guard, pinned
│   │                             egress, safe fetcher, content sniffing, HTML/text sanitising,
│   │                             injection detection, parser sandbox, data governance
│   ├── modules/                  bounded contexts (business capabilities)
│   │   ├── identity/  tenancy/  audit/  research/  sources/  documents/  knowledge/
│   │   ├── llm/  agents/  monitoring/  notifications/  security_center/
│   │   └── evaluation/  platform/
│   └── apps/                     process entry points (the only place that knows about HTTP)
│       ├── api/                  FastAPI app factory, middleware, dependencies, routers (v1)
│       ├── web/                  the web dashboard: static files served at /app, own CSP
│       ├── worker/               queue consumer
│       ├── scheduler/            leader-elected periodic duties
│       ├── evaluation/           evaluation runner (drives the public API in-process)
│       ├── ops_server.py         /metrics and health for the worker and scheduler
│       └── cli/                  `argus` admin command
├── migrations/                   Alembic environment and versions (run as the owner role)
├── prompts/                      versioned prompt files: prompts/<name>/v<N>.yaml
├── configs/                      data, not code: LLM routing and pricing, source reputation
├── evals/                        evaluation datasets (with the fixed corpus and red-team cases)
│                                 and the committed baseline
├── tests/                        unit/ integration/ security/ eval/ perf/
├── Dockerfile                    multi-stage, non-root, digest-pinned base images
├── docker-compose.yml            local stack: PostgreSQL + pgvector, Redis, Mailpit, ClamAV
│                                 (profile), migrate, api, worker, scheduler
├── docker/postgres/init/         role creation for the local PostgreSQL container
├── deploy/kubernetes/            Kustomize base, staging and production overlays (phase 23)
├── deploy/observability/         Prometheus rules, collector, Grafana dashboard, local stack
├── scripts/                      local PostgreSQL without Docker, load test, demo data
├── docs/                         architecture, ADRs, security, database, AI, phase guides, ops
└── .github/                      CI and release workflows, Dependabot
```

## Module anatomy

Each bounded context in `argus.modules.<name>` follows the same shape, so a reader always knows
where to look:

| File | Contains | May import |
|---|---|---|
| `models.py` | SQLAlchemy ORM tables for this context | `argus.infrastructure.db` |
| `schemas.py` | Pydantic models: commands, read models, API DTOs | `argus.core` |
| `repository.py` | queries; every tenant method takes a `TenantScope` | models |
| `service.py` | use cases: validation, authorisation hooks, transactions, audit | repository, other modules' services |
| `tasks.py` | queue task handlers (worker side) | service |

HTTP routers are **not** inside modules: they live in `argus.apps.api.v1` and translate HTTP to
service calls. That is why the worker and the CLI reuse the same services, and why an
import-linter contract can forbid `fastapi` inside `argus.modules`.

## Why not the layout proposed in the specification?

The specification sketched top-level `apps/`, `services/`, `domain/` and `infrastructure/`
directories and explicitly invited a better structure if one exists. Differences and reasons:

1. **One installable package under `src/`** instead of several top-level directories. Imports are
   absolute and unambiguous (`argus.modules.research`), tests run against the installed package
   (the `src` layout prevents accidentally importing the working tree), and the wheel is the
   deployable artefact.
2. **Vertical slices (`modules/<context>`) instead of horizontal layers (`services/`, `domain/`)**.
   A feature change touches one directory; horizontal layering scatters each feature across the
   tree and invites cross-feature coupling.
3. **A dedicated `security/` package** below the business modules so every module uses the same
   vetted primitives (one SSRF guard, one password hasher, one policy engine).
4. **Executable boundaries**: the layering is enforced by `import-linter` contracts
   (`pyproject.toml`), not by convention.
