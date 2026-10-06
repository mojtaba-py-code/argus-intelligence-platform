# Phase 1 - Foundation: repository, configuration, HTTP skeleton, database access

## 1. Purpose
Every later phase needs the same things: settings it can trust, logs that never leak secrets, a
consistent error format, a database session that carries the tenant context, and quality gates
that run from the first commit. Phase 1 builds exactly that and nothing more.

## 2. Architecture
```
request ─▶ RequestContext ─▶ SecurityHeaders ─▶ Timeout ─▶ BodySizeLimit ─▶ CORS ─▶ router
              │ request id, client IP (trusted proxies), host allow-list,
              │ credentials-in-URL rejection, access log, metrics
              ▼
        exception handlers ─▶ RFC 9457 problem+json (no internals)
```
The app factory (`argus.apps.api.main.create_app`) receives `Settings` and optionally a prebuilt
`Container` - the composition root that owns the database engine, Redis client, clock and metrics.

## 3. Why these technologies
* **pydantic-settings** - configuration is data with a schema; validation at start-up turns a
  misconfiguration into a refusal to start instead of a 3 a.m. incident.
* **structlog** - one JSON object per event with context variables; a processor chain is the
  natural place to put redaction, so it cannot be forgotten at a call site.
* **Pure ASGI middleware** - `BaseHTTPMiddleware` buffers bodies and interferes with cancellation;
  pure ASGI lets the body-size limit act *while* the body streams in.
* **SQLAlchemy 2.1 async + asyncpg** - typed, parameterised by construction.
* **Alembic run by an owner role** - the application role cannot change the schema.

## 4. Security considerations (and where they live)
| Concern | Control | Code |
|---|---|---|
| Insecure production config | 17 production rules; the process refuses to start | `core/config.py::_production_problems` |
| Typos in security settings | unknown `ARGUS_*` variable = error with a suggestion | `core/config.py::check_unknown_variables` |
| Secrets in config errors | Pydantic's `input_value` stripped from messages | `core/config.py::build_settings` |
| Secrets in logs | redaction processor (by key and by credential shape) on every event, including library logs and tracebacks | `core/redaction.py`, `core/logging.py` |
| Credentials in URLs | requests with `?access_token=`/`?api_key=`... are rejected | `apps/api/middleware.py` |
| Host header attacks | allow-list | same |
| Spoofed client IP | `X-Forwarded-For` trusted only from configured proxies, walked right-to-left | `resolve_client` |
| Big/slow requests | byte cap that also holds for chunked bodies; per-request deadline | `BodySizeLimitMiddleware`, `TimeoutMiddleware` |
| Information leakage in errors | fixed public messages; validation errors never echo input | `apps/api/problems.py` |
| Over-privileged DB access | runtime role without DDL/BYPASSRLS; statement/lock/idle timeouts | `infrastructure/db/engine.py`, `migrations/versions/0001_baseline.py` |
| Tenant context leaking across pooled connections | `set_config(..., is_local => true)` per transaction | `Database.session` |

## 5. Directory structure introduced
`src/argus/{core,infrastructure,security,modules,apps}`, `migrations/`, `tests/{unit,integration}`,
`docker/`, `.github/`, `docs/`. See [repository-structure.md](../architecture/repository-structure.md).

## 6. Important files
* `core/config.py` - settings, production guards, `*_FILE` secrets, typo protection.
* `core/errors.py` - the error hierarchy; every error has a stable `code`.
* `core/redaction.py` - what counts as a secret.
* `core/crypto.py` - AES-GCM keyring with key ids and associated data.
* `infrastructure/db/engine.py` - `Database.session()` / `Database.tenant()`.
* `infrastructure/db/migration_support.py` - one implementation of RLS policies and grants.
* `apps/api/middleware.py`, `apps/api/problems.py`, `apps/api/main.py`.

## 7. Implementation notes worth reading in the code
* `BodyTooLarge` subclasses Starlette's `HTTPException`: FastAPI converts *any other* exception
  raised while reading a body into a generic 400, which would hide the 413.
* The readiness probe compares `alembic_version` with the script head, so a deploy that forgot to
  migrate is not marked ready.
* `reject_unknown_query_parameters` walks the route's dependency tree because FastAPI silently
  ignores undeclared parameters - a typo like `?limt=5` would otherwise "work".

## 8. Tests
`tests/unit/test_config.py`, `test_redaction.py`, `test_kernel.py`, `test_api_foundation.py`;
`tests/integration/test_database_foundation.py`, `test_migrations.py`. Integration tests create a
throwaway database, migrate as the owner role, and run as the restricted role.

## 9. Common mistakes this phase avoids
1. Reading `X-Forwarded-For` unconditionally (rate-limit and audit bypass).
2. Returning Pydantic's default 422, which echoes the submitted password back.
3. `create_all()` at start-up instead of migrations (no history, no review, owner = app role).
4. One database role for everything (an SQL injection becomes a schema takeover).
5. Logging `request.headers` "just for debugging".

## 10. Scalability
The API is stateless; middleware keeps no per-process state that matters across replicas.
Metrics use route templates (bounded cardinality).

## 11. How it connects to later phases
Phase 2 adds models, the first RLS-free identity tables and the audit chain on top of
`Database.session()`. Phase 3 introduces `TenantScope`-based units of work and RLS policies via
`migration_support.tenant_rls()`. Every phase reuses the error model and the redaction pipeline.

## 12. Acceptance criteria (all automated)
- [x] `ruff`, `ruff format --check`, `mypy --strict`, `lint-imports` (4 contracts) green.
- [x] Production configuration with defaults refuses to start and names every variable to fix.
- [x] An unhandled exception returns a problem document without message, path or DSN.
- [x] A chunked body over the limit returns 413; a slow handler returns 504.
- [x] The runtime role is not superuser, cannot `CREATE TABLE`, has no `BYPASSRLS`.
- [x] Migrations upgrade → downgrade → upgrade cleanly; models match migrations.
