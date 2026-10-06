# Argus — Enterprise AI Intelligence & Research Platform

[![CI](https://github.com/mojtaba-py-code/argus-intelligence-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/mojtaba-py-code/argus-intelligence-platform/actions/workflows/ci.yml)
[![CodeQL](https://github.com/mojtaba-py-code/argus-intelligence-platform/actions/workflows/codeql.yml/badge.svg)](https://github.com/mojtaba-py-code/argus-intelligence-platform/actions/workflows/codeql.yml)
[![Python 3.12 | 3.13 | 3.14](https://img.shields.io/badge/python-3.12%20%7C%203.13%20%7C%203.14-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![Type-checked: mypy strict](https://img.shields.io/badge/mypy-strict-1f5082)](pyproject.toml)
[![Code style: Ruff](https://img.shields.io/badge/code%20style-ruff-D7FF64?logo=ruff&logoColor=black)](https://docs.astral.sh/ruff/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Argus turns a research question into a verified, cited report. It plans the research, collects
evidence from the web and from an organisation's own documents, analyses it with AI agents,
checks every claim against its sources, flags contradictions, and keeps watching the web for
changes that matter - for many organisations at once, each isolated from every other.

Security is the design constraint, not a feature added at the end: tenant isolation is enforced
by PostgreSQL row-level security, everything fetched from the web or uploaded is treated as
hostile, AI agents can only use tools they were explicitly given, and every security-relevant
action lands in a tamper-evident audit log.

## What it does

| Area | Highlights |
|---|---|
| Research jobs | plan → collect → analyse → verify → detect contradictions → report; budgets, human approvals, progress streaming; reports in Markdown, JSON, CSV and PDF |
| Knowledge base | PDF, DOCX, HTML, Markdown, CSV, JSON and text; malware scan, parsing in a sandboxed subprocess, chunking, embeddings; hybrid keyword + vector search with authorisation inside the SQL |
| Secure web research | SSRF guard with DNS pinning and per-hop redirect checks, size/time/decompression limits, robots.txt and per-domain politeness, source reputation |
| AI agents and LLM gateway | declared tool catalogue, per-agent permissions and budgets, kill switches; Claude (Anthropic), OpenAI-compatible and offline local models; data-classification policy before any text leaves |
| Evidence verification | every finding needs a verified quote; figures must appear in the evidence; contradictions and confidence scores; prompt-injection defences end to end |
| Continuous monitoring | watched pages and searches, change significance scoring, in-app and e-mail notifications |
| SaaS operation | organisations, roles, restricted projects, API keys and service accounts; plans and quotas; retention; suspension, deletion with a grace period, restore, purge; owner data export |
| Security center | audit chain verified daily, security events and recommendations, denied-access auditing, kill-switch administration |
| Observability | OpenTelemetry traces, Prometheus metrics, alert rules with runbooks, Grafana dashboard |
| Web dashboard | `/app`: projects, active jobs, reports, sources, knowledge base, monitoring, alerts, AI usage and costs, system health, security events |

## Architecture

```
            browser (/app)  ·  API clients (bearer tokens, API keys)
                              │ HTTPS
                ┌─────────────▼──────────────┐
                │ argus api (FastAPI)        │  authentication, RBAC, rate limits, CSP, audit
                └─────────────┬──────────────┘
  modules: identity · tenancy · research · sources · documents · knowledge · llm · agents ·
           monitoring · notifications · security_center · evaluation · platform
                              │
   PostgreSQL 16 + pgvector (RLS)  ·  Redis (limits, cache)  ·  object storage (encrypted)
                              ▲
   argus worker (documents, research, monitoring)  ·  argus scheduler (periodic duties)
```

One installable package (`src/argus`): a modular monolith whose layers (apps → modules →
security → infrastructure → core) are enforced by import-linter. Details:
[system architecture](docs/architecture/system-architecture.md) ·
[database design](docs/database/database-design.md) ·
[AI architecture](docs/ai/ai-architecture.md) ·
[security model](docs/security/security-model.md) ·
[threat model](docs/security/threat-model.md).

## Quick start

### Option A - Docker Compose
```bash
cp .env.example .env                        # then replace every change-me password
uv run argus keys generate --quote >> .env  # signing, encryption and audit keys
docker compose up --build                   # PostgreSQL, Redis, Mailpit, migrate, api, worker, scheduler
docker compose run --rm api users create --email you@example.com --name "Your Name"
```
Open http://localhost:8000/ (the dashboard) and http://localhost:8000/docs (interactive API docs,
development only). Real malware scanning: `docker compose --profile scanning up --build` with
`ARGUS_DOCUMENTS__SCANNER=clamav`.

### Option B - local processes, no Docker
```bash
uv sync --group localdb                                       # Python 3.12 environment + pgserver
uv run python scripts/local_postgres.py start --data var/pg   # prints the DSNs to put in .env
uv run argus keys generate --quote >> .env
uv run argus db migrate                                       # as the schema owner role
uv run argus serve                                            # terminal 1: http://localhost:8000
uv run argus worker                                           # terminal 2
uv run argus scheduler                                        # terminal 3
uv run python scripts/seed_demo.py                            # optional: a demo organisation
```
`seed_demo.py` creates a demo organisation with documents, a real report (from the offline
models), a queued job and a monitor change, and writes the demo sign-in to `.env.demo`
(git-ignored).

No API key is needed to try Argus: without provider keys it runs on deterministic offline models.
To use Claude, install the extra (`uv sync --extra anthropic`) and set
`ARGUS_LLM__ANTHROPIC_API_KEY`. For Claude Opus 5.5 and Sonnet 5.5 the server-side refusal
fallback is **enabled by default**; turn it off with `ARGUS_LLM__ANTHROPIC_REFUSAL_FALLBACK=false`.

## Configuration
Every setting is an environment variable `ARGUS_<SECTION>__<NAME>` (a `.env` file is read too);
[.env.example](.env.example) lists the important ones. `argus config check` validates the
configuration for its environment: staging and production refuse unsafe values (public API docs,
wildcard hosts or origins, non-https URLs, missing secrets, unencrypted database connections, the
development scanner) and name the variable to fix. `argus config show` prints the effective
configuration with secrets redacted.

| Setting | Default | Purpose |
|---|---|---|
| `ARGUS_ENVIRONMENT` | `development` | `development`, `testing`, `staging` or `production` |
| `ARGUS_DATABASE__URL` / `ARGUS_DATABASE__MIGRATION_URL` | - | runtime role / schema owner (migrations and operator commands only) |
| `ARGUS_REDIS__URL` | none | shared rate limits and caches; in-process fallbacks in development |
| `ARGUS_PLATFORM__DEFAULT_PLAN` | `enterprise` | plan of new organisations (`free` for a hosted service) |
| `ARGUS_HTTP__WEB_DASHBOARD` | `true` | serve the dashboard at `/app` |
| `ARGUS_LLM__ANTHROPIC_API_KEY` | none | Claude; without any provider key the offline models are used |
| `ARGUS_OBSERVABILITY__OTEL_ENABLED` | `false` | export traces over OTLP |

## Command line
| Command | What it does |
|---|---|
| `argus serve` · `worker` · `scheduler` | the three process roles |
| `argus db migrate` · `current` · `check` | migrations (owner role); drift check between models and migrations |
| `argus keys generate` | new key material for `.env` or the secret store |
| `argus users create` · `disable` · `enable` | administrative accounts; containing a compromised account in one step |
| `argus orgs list` · `suspend` · `resume` · `restore` · `set-plan` · `purge` | organisation lifecycle and plans (audited, with a reason) |
| `argus audit verify` · `export` · `prune` | verify every chain, write an evidence copy, retention behind a signed checkpoint |
| `argus killswitch` | stop an agent, tool, provider, model or all AI, platform-wide |
| `argus jobs` · `prompts` · `eval` · `config` | queue inspection, prompt deployments, evaluation gate, configuration |

## Tests and quality gates
```bash
uv run pytest                     # unit and security tests (database tests are skipped)
ARGUS_TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:5432/postgres uv run pytest   # everything: + integration, API surface, red team, evaluation
uv run pytest -m perf             # benchmarks with latency budgets (needs the database)
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run lint-imports
uv run bandit -c pyproject.toml -r src
```
Integration tests create a throwaway database per run and run as the runtime role, so row-level
security takes part in every test. CI adds dependency auditing, CodeQL, secret scanning,
container scanning, signed releases with SBOM and provenance, and Kubernetes manifest
validation.

## Documentation
* [Roadmap](docs/roadmap.md) and a teaching guide per phase in [docs/phases](docs/phases/):
  purpose, architecture, security, files, tests, common mistakes, acceptance criteria.
* Operations: [deployment](docs/operations/deployment.md) ·
  [backup and restore](docs/operations/backup-restore.md) ·
  [incident response](docs/operations/incident-response.md) ·
  [disaster recovery](docs/operations/disaster-recovery.md) · [alerts](docs/operations/alerts.md).
* Decisions: [architecture decision records](docs/architecture/decisions/) and the
  [review of the original specification](docs/spec-review.md).

## Status
Phases 1-25 of the [roadmap](docs/roadmap.md) are complete, except phase 18 (knowledge graph),
which was left out by decision. Version 0.1.0.

## Security
Please report vulnerabilities privately - see the [security policy](SECURITY.md). The design is
documented in the [security model](docs/security/security-model.md) and
[threat model](docs/security/threat-model.md).

## Contributing
Contributions are welcome: read the [contributing guide](CONTRIBUTING.md) and the
[code of conduct](CODE_OF_CONDUCT.md) first.

## License
[MIT](LICENSE)
