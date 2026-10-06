# Contributing to Argus

Thank you for helping. This guide covers the development setup, the quality gates every change
must pass, and how to propose a change.

## Development setup

You need [uv](https://docs.astral.sh/uv/) and Python 3.12 or newer. Docker is optional.

```bash
uv sync --all-extras          # locked environment: runtime, all extras and the dev tools
uv run pre-commit install     # fast local gates on every commit (format, lint, types, secrets)
```

The database-backed tests need PostgreSQL + pgvector and a superuser DSN in
`ARGUS_TEST_DATABASE_URL`; each run creates and drops its own throwaway database. With Docker,
`docker compose up -d postgres` and use
`postgresql://postgres:<POSTGRES_SUPERUSER_PASSWORD>@127.0.0.1:5432/postgres`. Without Docker:

```bash
uv sync --all-extras --group localdb
uv run python scripts/local_postgres.py start --data var/pg   # prints ARGUS_TEST_DATABASE_URL
```

On Windows, keep the virtual environment and data directory on a short ASCII-only path;
PostgreSQL's DLL loading fails on long or non-ASCII paths.

## Quality gates

CI runs all of these on every pull request; run them locally first.

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy                       # strict
uv run lint-imports               # architecture contracts
uv run bandit -c pyproject.toml -r src
uv run pytest                     # unit, security and evaluation tests
ARGUS_TEST_DATABASE_URL=<superuser DSN> uv run pytest --cov   # + integration, red team, e2e
node --test tests/web/dashboard.test.mjs
```

Coverage must stay at or above the floor in `pyproject.toml`.

## Making a change

1. Open an issue first for anything larger than a small fix, so the design can be agreed.
2. Branch from `main`, keep the change focused, and add tests that fail without it.
3. Security-relevant changes need a regression test in `tests/security/` and, where a guarantee
   changes, an update to [the security model](docs/security/security-model.md).
4. Schema changes need an Alembic migration in `migrations/versions/`; `argus db check` must
   report no drift.
5. Architectural decisions get an [ADR](docs/architecture/decisions/).
6. Write commit messages in the imperative mood (`Add retention for export jobs`) and explain
   *why* in the body when it is not obvious.
7. Open a pull request and fill in the template; CI must be green before review.

## Ground rules

* Never commit secrets, real credentials or personal data - `.env` files are git-ignored, and
  gitleaks runs in pre-commit and CI.
* Treat every fetched page, uploaded file and model output as hostile input.
* New outbound network calls go through `argus.security.fetcher`; new model calls go through the
  LLM gateway (`argus.modules.llm`). Import-linter enforces both.
* Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), never in an issue.

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE)
and that you follow the [code of conduct](CODE_OF_CONDUCT.md).
