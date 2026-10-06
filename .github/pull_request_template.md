## What and why

<!-- What does this change do, and why is it needed? Link the issue: "Closes #123". -->

## How it was tested

<!-- New or changed tests, and anything verified by hand. -->

## Checklist

- [ ] `ruff check`, `ruff format --check`, `mypy`, `lint-imports` and `bandit` pass locally
- [ ] Tests added or updated; the full suite passes with `ARGUS_TEST_DATABASE_URL` set
- [ ] Security-relevant behaviour has a regression test in `tests/security/`
- [ ] Schema changes include an Alembic migration and `argus db check` reports no drift
- [ ] Documentation (README, `docs/`, ADRs) updated where behaviour changed
- [ ] No secrets, credentials or personal data in the diff
