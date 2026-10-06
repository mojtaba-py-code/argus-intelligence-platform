# Technology Selection

Every choice below answers three questions: *why this*, *what we rejected*, and *what it costs us*.
Significant decisions have an Architecture Decision Record in [decisions/](decisions/).

| Concern | Choice | Why | Rejected alternatives |
|---|---|---|---|
| Language | Python 3.12+ (CI: 3.12, 3.13, 3.14) | the AI/data ecosystem lives here; `asyncio` fits an I/O-bound platform | Go (weaker AI tooling), Node (weaker data tooling) |
| API framework | FastAPI on Starlette + Uvicorn | async-native, Pydantic validation at the edge, OpenAPI for free | Django (sync ORM heritage, heavier), Flask (no native async validation) |
| Validation | Pydantic v2, `extra="forbid"` + strict types on every request model | unknown fields and lax coercions (`"0"` → `False`) are rejected instead of silently accepted | marshmallow (slower, less typing integration) |
| Configuration | pydantic-settings, nested env vars, `*_FILE` secret files | typed, validated at start-up; production refuses insecure settings | dynaconf (untyped), raw `os.environ` |
| Relational store | PostgreSQL 16+ | transactions, RLS, `SKIP LOCKED`, `LISTEN/NOTIFY`, full-text search, pgvector - one system covers relational, queue, search and vectors | MySQL (no RLS), MongoDB (no multi-row transactions at the level we need) |
| ORM / SQL | SQLAlchemy 2.1 (typed ORM + Core), asyncpg driver | parameterised by construction, typed models, mature migrations | raw asyncpg everywhere (easy to concatenate SQL by mistake), Tortoise (smaller ecosystem) |
| Migrations | Alembic, run by a dedicated **owner** role | the runtime role cannot alter schema | `create_all()` at start-up (no history, no review) |
| Vectors | pgvector (HNSW, cosine) in the same database | authorisation filters and deletes are in the same transaction as the source rows - deletion guarantees are trivial | Qdrant/Weaviate/Pinecone (second source of truth, cross-system deletes, extra auth surface) - kept as a future adapter for very large tenants. ADR [0004](decisions/0004-pgvector-hybrid-retrieval.md) |
| Keyword search | PostgreSQL full-text (`tsvector` generated column + GIN) | hybrid retrieval with no extra service | Elasticsearch/OpenSearch (operational weight) |
| Queue | PostgreSQL table + `SKIP LOCKED` leases + `LISTEN/NOTIFY` | **transactional enqueue** (job row and queue entry commit together), durable, inspectable with SQL | Celery/RQ/arq on Redis (dual-write problem, Redis becomes a source of truth), Kafka (overkill). ADR [0003](decisions/0003-postgres-job-queue.md) |
| Cache / rate limits | Redis 7 with Lua (GCRA) | atomic multi-level limits shared across API replicas | in-process limits (wrong with >1 replica), PostgreSQL counters (hot rows) |
| Object storage | S3-compatible (MinIO in development), encrypted local-filesystem adapter | private buckets, presigned URLs, lifecycle rules | storing blobs in PostgreSQL (bloat, backup size) |
| Password hashing | Argon2id (`argon2-cffi`), OWASP parameters, transparent re-hash | memory-hard, winner of the Password Hashing Competition | bcrypt (72-byte limit, not memory-hard), PBKDF2 |
| Access tokens | JWT signed with **Ed25519 (EdDSA)**, 10-minute lifetime, `kid` rotation, JWKS endpoint | asymmetric: services can verify without the signing key; no `alg` confusion because the verifier pins `EdDSA` | HS256 (every verifier holds the forging key) |
| Refresh tokens | opaque 256-bit random strings, stored hashed, rotated on every use with **reuse detection** | a stolen-and-replayed refresh token revokes the whole session family | JWT refresh tokens (cannot be revoked without a lookup anyway). ADR [0005](decisions/0005-token-architecture.md) |
| MFA | TOTP (RFC 6238) with encrypted secrets, replay protection, hashed recovery codes | works with any authenticator app, no SMS (SIM-swap) | SMS OTP |
| Encryption at rest (app level) | AES-256-GCM envelope encryption with key ids (rotation without re-encrypting everything at once) | protects MFA secrets and stored documents even if a database dump leaks | Fernet (no key ids / AAD), custom crypto (never) |
| HTTP egress | httpx + a custom **httpcore network backend** that resolves, validates and *pins* the IP it connects to | closes DNS-rebinding TOCTOU; redirects re-validated hop by hop | URL-string allow-lists (bypassable by DNS), `requests` (sync) |
| HTML parsing | selectolax (lexbor HTML5 parser), never a browser | fast, robust against malformed markup, no script execution | BeautifulSoup+lxml (slower), headless Chrome (executes attacker JavaScript - only ever inside an isolated browser worker, out of scope by default) |
| HTML sanitising | nh3 (Rust ammonia) | allow-list sanitiser maintained against mXSS | bleach (deprecated) |
| PDF / DOCX | pypdf; DOCX read directly from the ZIP with defusedxml | small attack surface, XXE-safe, limits enforced before decompression | python-docx (uses lxml with entity resolution defaults we would need to override), Apache Tika (JVM sidecar) |
| robots.txt | Protego | supports `*`/`$` wildcards and `Crawl-delay`; `urllib.robotparser` does not | urllib.robotparser |
| LLM access | provider-agnostic **LLM gateway**; Claude through the official `anthropic` SDK; OpenAI-compatible adapter (OpenAI, vLLM, Ollama); deterministic local extractive provider | model routing, fallback, budgets, data governance and audit in one place; the platform keeps working offline and in tests | LangChain (hides prompts, retries and costs behind abstractions we must control for security). ADR [0006](decisions/0006-llm-gateway.md) |
| Default models | `claude-opus-5-5` for planning, analysis, verification and reports; `claude-sonnet-5-5` / `claude-haiku-4-5` for bulk extraction and classification (cost-aware routing, configurable per task) | quality where reasoning matters, cost control where volume matters | single-model everywhere (cost), smallest-model everywhere (quality) |
| Prompts | versioned YAML files rendered by a Jinja2 **SandboxedEnvironment**, active version per environment stored in the database | code-reviewed, testable, roll back without redeploying | prompts inline in Python strings |
| Agents | code-orchestrated **plan-then-execute** pipeline; agents are declarative specs with tool allow-lists and budgets enforced by a runtime | control flow is decided from trusted input, not from scraped text. ADR [0007](decisions/0007-agent-security-model.md) | free-form autonomous agent loops with every tool |
| Logging | structlog JSON with a **redaction processor** and context variables | one structured line per event; secrets scrubbed before any sink | stdlib logging format strings |
| Metrics / tracing | Prometheus client; OpenTelemetry SDK + OTLP | vendor-neutral | vendor agents |
| Testing | pytest, pytest-asyncio, Hypothesis (property tests for the SSRF parser), respx, fakeredis (Lua), real PostgreSQL for integration tests | RLS, `SKIP LOCKED` and pgvector cannot be faked honestly | SQLite for "integration" tests (no RLS) |
| Quality gates | Ruff (lint + format), mypy `--strict`, import-linter, Bandit, Semgrep, pip-audit, gitleaks | each catches a different class of defect | - |
| Containers | multi-stage Dockerfile, non-root UID 10001, read-only root filesystem, `cap_drop: ALL` | minimal blast radius | single-stage images running as root |

## Version policy

Direct dependencies use compatible-release ranges in `pyproject.toml`; exact versions (with hashes)
are pinned in `uv.lock`. Dependabot proposes updates with a cooldown; CI runs `pip-audit` on the
locked set. Frameworks that break on minor versions (FastAPI `0.x`) are pinned to a minor series.
