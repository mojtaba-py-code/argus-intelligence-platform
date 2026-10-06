# Phase 25 - Final security hardening

## 1. Purpose
Close the build the way a security team would before a first customer: review the whole system
against its threat model with fresh eyes, run every gate at once (the complete test suite,
static analysis, dependency audit, migration drift check), fix what the review finds, and make
the documentation true - then keep it true with tests.

## 2. How the review was done
* **Independent reviews of the newest code.** Two read-only reviews, each given only the code
  and the design intent, looked for defects with a concrete failure scenario: one over the SaaS
  layer (quotas, retention and audit pruning, lifecycle, exports, dashboard API, migration 0014),
  one over the web dashboard (router, page, script, CSP and headers). Each reported finding was
  checked against the code before it was fixed, and each fix got a test that fails without it.
* **The threat model, threat by threat.** Every threat (A1-A9, T1-T5, W1-W7, D1-D6, R1-R5,
  P1-P10, X1-X13, and S1-S12 added in phase 24) names its mitigation and the test that proves
  it; the security testing map in [threat-model.md](../security/threat-model.md#6-security-testing-map)
  links each group to its tests.
* **Dynamic testing.** The OpenAPI-driven API surface suite (`tests/security/test_api_surface.py`)
  is the platform's DAST: every operation is called anonymously, as another tenant's owner and
  API key, and with hostile path segments, query strings and bodies; routes outside the OpenAPI
  document must be on a reviewed list. The red-team suite drives a worst-case obedient model.
  The web dashboard's script runs against its real page in a behaviour suite.
* **Every gate together.** `pytest` with coverage (unit, integration, security, end-to-end, AI
  evaluation), `ruff`, `ruff format --check`, `mypy --strict` over source and tests, the four
  import-linter contracts, `bandit`, `pip-audit`, and `argus db check` against a migrated
  database.

## 3. Findings and fixes
No critical or high finding. Every medium and low one was fixed; none is accepted as a residual
risk.

### SaaS layer
| Severity | Finding | Fix | Test |
|---|---|---|---|
| Medium | The dashboard aggregate checked only `org:read`: an API key scoped to `org:read` (403 on `/projects`) read project, job and report titles through it | each section requires the permission of the endpoint behind it; unreadable sections are `null` | `test_dashboard_respects_what_each_viewer_may_see` |
| Medium | Exports packed quarantined and unscanned files (a way around the quarantine), and one missing or damaged file failed every export of the organisation | only downloadable documents; damaged files are listed in the manifest | `test_exports_leave_out_quarantined_files_and_survive_a_damaged_one` |
| Medium | Purge and restore were not coordinated: an organisation could be restored while its files were being deleted, or after a purge failed half-way; a purge that deleted nothing still recorded `org.purged` | new state `purging`, committed before any file is touched (no restore after it, members see nothing, the next run finishes); the final delete is checked | `test_suspension_deletion_restore_and_purge` |
| Medium | An archive was held in memory several times over (a large one could exhaust a shared API process; past 2 GiB it could not be sealed at all); a failed upload left the export pending for three hours | lower cap (128 MiB default, 1 GiB maximum), archive size limit below the encryption limit, two decryptions at a time per process, upload failures handled like build failures | download-slot check in `test_owners_export_everything...` |
| Low | Retention took the most recently *fetched* version for the current page, but content that comes back reuses its old row: the current page could be deleted | "current" = most recently seen (`last_seen_at`), also in exports | `test_retention_keeps_current_content_and_prunes_audit_behind_a_checkpoint` |
| Low | Pruning freed the sequence numbers below a checkpoint and verification starts above it: a forged row placed there would never be checked | an insert trigger refuses rows at or below a checkpoint; verification reports any that exist (`rows below the checkpoint`) | same test |
| Low | Re-sending an invitation at full capacity was refused although it changes nothing | the open invitation is revoked before the seats are counted | `test_free_plan_quotas_are_enforced_and_reported` |
| Low | `argus audit prune` enforced only the 90-day floor (not the chain's own retention or the platform's 730 days) and reported success for a mistyped chain | the owed retention is the minimum; unknown or malformed chains are refused | `test_operators_cannot_prune_less_than_a_chain_is_owed` |
| Low | Two concurrent export requests could both start one | partial unique index: one pending export per organisation | `test_concurrent_export_requests_start_only_one` |
| Low | Docstrings that did not match the code (dashboard snapshot, where the export carries the verification, suspended organisations being deletable); the checkpoint missing from evidence copies | dashboard now really reads one snapshot; export manifests and `argus audit export` carry the signed checkpoint; docstrings corrected | - |
| Low | `audit_checkpoints` readable across tenants by the runtime role; a downgrade below 0014 would silently make pruned chains unverifiable | row-level security (own chain only); the downgrade refuses to run once a chain was pruned | migration round trip in CI |

### Web dashboard
| Severity | Finding | Fix | Test (`tests/web/dashboard.test.mjs`) |
|---|---|---|---|
| Medium | A page restored from the back/forward cache showed the previous dashboard after its session had been revoked | the page clears itself on `pagehide` when the browser keeps it | back/forward cache |
| Low | Sign-out kept the dashboard on screen until the server answered | the page forgets first, then tells the server | sign-out before the server answers |
| Low | Late answers were applied to whatever was on screen: a refresh after sign-out revived the session, an error for the previous organisation wiped the new one, an old overview could render for the next user | session epochs: answers for a previous session or organisation are dropped | refresh; organisation switch |
| Low | A slower report could replace the one on screen | each opening has a sequence number | report race |
| Low | Polling rebuilt every card each minute (focus lost, a report dialog's return target gone) and announced the update to screen readers each time | unchanged data leaves the page alone; focus follows its element; no live announcement | polling and focus |
| Low | Focus was lost after a failed sign-in | focus returns to the control | failed sign-in |
| Low | The security-recommendation count showed at most 5 | the API sends the full count | - |
| Low | `If-None-Match` compared exactly: no 304 behind a proxy that weakens ETags | RFC 9110 weak comparison, lists and `*` | `test_if_none_match_is_compared_weakly` |
| Low | Without an organisation the idle check ran only every eight minutes, and Refresh could not find a new membership | the poll runs regardless; Refresh looks for memberships again | - |
| Low (latent) | A refresh without a refresh token could leave the "one at a time" guard stuck | the guard is set only for a started refresh | - |

### Found by the gates
* A wall-clock assertion in the collection concurrency test failed on a loaded machine; it now
  counts concurrent requests instead of timing them.
* The benchmarks bulk-loaded 10,000 passages and analysed them, but did not vacuum: PostgreSQL
  then started an autovacuum on its own in the middle of the measurements (one list's p95 rose
  to about 800 ms). They now run `VACUUM (ANALYZE)` after loading, as any bulk load should. The
  ten-parallel-requests budget was the only one tighter than the documented "about three times
  the laptop" rule (2.3x); it is now 3x the laptop's p95, like the others.
* One file was not formatted; `ruff format --check` is clean.

Each fix to the dashboard script was verified the other way round as well: re-introducing the
bug makes its behaviour test fail.

### Results on the final tree
* `pytest` (unit, integration, security, end-to-end, AI evaluation, the dashboard's behaviour
  suite): **941 passed, 2 skipped** - the benchmarks (run with `pytest -m perf`) and one test of
  POSIX resource limits that cannot run on Windows.
* Coverage **86%** with branches; CI now fails below 85% (`fail_under`).
* `pytest -m perf`: every budget met (on a laptop with other applications using about 70% of its
  CPU, so the absolute numbers are higher than in phase 21).
* `ruff`, `ruff format --check`, `mypy --strict` (274 files), the four import-linter contracts,
  `bandit`: clean. `pip-audit`: no known vulnerabilities. `argus db check`: no drift; migration
  0014 downgrades and upgrades again.

## 4. Documentation
* The README was written: what Argus does, architecture, quick start with Docker Compose or
  local processes, configuration, the command line, tests and quality gates.
* Guides 21-23 gained the sections every guide has (security, tests, common mistakes,
  scalability, next phases), and the repository-structure and system-architecture documents
  were brought in line with the code.
* Claims that were no longer true were corrected (for example an incident control - "pause
  workers by queue" - that never existed; the security model now says to scale workers to zero).
* `tests/unit/test_docs.py` keeps it that way: every relative link in the README and `docs/`
  resolves, every finished roadmap phase has its guide, the role-permission matrix in the
  security model is the one the code enforces, and so is the list of permissions an API key can
  never carry.

## 5. Files
`docs/phases/phase-25-hardening.md`, `README.md`, `tests/unit/test_docs.py`,
`tests/web/dashboard.test.mjs`, the documents listed above, and the fixes in section 3 (platform
module, migration 0014, audit service, tenancy authorisation and invitations, CLI, web
dashboard).

## 6. Acceptance criteria
* Every threat in the threat model has a mitigation in code and a test; accepted residual risks
  are written down.
* The complete test suite and every static gate pass on the final tree.
* Documentation links resolve and the documented permission model matches the code.
