# Phase 19 - Advanced security

## 1. Purpose
Security controls existed from phase 1; this phase gives the people responsible for an
organisation the means to **watch** them and **act** on them:

* know that the audit log is still intact - checked on a schedule, not only when someone thinks
  of running a command;
* stop an agent, a tool, a model provider or all AI activity for their organisation in one call,
  and see who did it;
* see the organisation's security posture on one page: refused actions, agent tool denials,
  prompt-injection detections, blocked egress, model policy blocks, credentials hygiene - with
  advice that follows from the numbers;
* have members' refused actions in the audit trail, so probing is visible;
* prove, automatically and for every endpoint, that authentication and tenant isolation hold.

Session-anomaly signals and new-sign-in alerts from the original plan were left out by decision.
Secret-scanning patterns for the platform's key format already existed (`.github/gitleaks.toml`).

## 2. Architecture
```
scheduler (leader) ── every 15 min ──► argus_audit_verification_due(batch, now - 24 h)
                                       SECURITY DEFINER: organisation ids only
        └─ AuditIntegrity.verify(org)
              snapshot transaction (REPEATABLE READ, read only), org RLS context:
                  AuditService.verify_chain - head first, rows streamed in keyset pages,
                  genesis hash + sequence from 1, HMAC per row, tail vs head
              audit_verifications row (+ 90-day retention)
              newly broken? ── audit.integrity_failed (own transaction)
                            └─ Event security.audit.integrity_failed → owners/admins (in-app + e-mail)

API  /orgs/{org}/security/summary              audit:read     posture.py: counts in tenant RLS
     /orgs/{org}/security/events               audit:read     denied/failed + authn/authz/security
     /orgs/{org}/security/kill-switches        audit:read     own + platform (read-only)
         POST / DELETE /{id}                   security:manage (never on API keys)
     /orgs/{org}/security/audit-verifications  audit:read; POST = security:manage, 6/h

any route ── org_access/project_access ── membership proven ──► request.state (OrgAccess)
         └─ PermissionDenied anywhere later ──► error handler hook
                 └─ SecurityCenterService.record_denial: 30 per principal per 10 min
                    → audit access.denied {method, route template, permission, detail}
```

## 3. Why this design
* **Verification inside the tenant's own context.** The scheduler's only cross-tenant read is a
  list of organisation ids; each chain is then read with that organisation's RLS context, so the
  job can never show one tenant's audit rows to another. The platform chain (logins) belongs to
  nobody and stays an operator task (`argus audit verify`, owner role).
* **Snapshot isolation.** Under READ COMMITTED, an append committing between "read the rows" and
  "read the head" looks exactly like a deleted tail. A REPEATABLE READ transaction
  (`Database.session(snapshot=True)`) gives every statement the same view.
* **Start from the genesis hash.** The previous verifier started from the first row it found, so
  deleting the oldest rows went unnoticed. The chain must now start at sequence 1 with the
  all-zero hash.
* **Announce a break once.** A broken chain stays broken until someone investigates; re-alerting
  every day trains people to ignore the alert. A *different* break (another position or reason)
  is announced again.
* **The alert does not depend on the audit log working.** Whoever broke the chain may also block
  appends (a forged row occupying the next sequence number). The verification result is stored
  first and the audit event is written in its own transaction, so the alert always goes out.
* **Kill switches need a human administrator.** `security:manage` is excluded from API-key
  scopes: an automation credential, if stolen, cannot stop or resume AI activity. Targets are
  validated against the declared agents, tools and providers - a typo ("analyzer") must not leave
  someone believing the analyst stopped.
* **Denials are audited where membership is proven.** The organisation access is attached to
  the request only after the authoriser established membership; a non-member's 404 never writes
  into the tenant's log. A per-principal budget keeps one member from flooding it.
* **Advice is code, not a model.** Recommendations are deterministic rules over counts, and
  their messages contain numbers and fixed words only - stored text (a kill-switch reason, an
  injected page) never reaches the dashboard through them.

## 4. Security
| Threat | Control |
|---|---|
| Audit rows edited, deleted (first, middle, last) or appended behind the head | full recomputation from genesis; tail compared with the head; scheduled; alert per break (threat X1) |
| Stolen API key stops or resumes AI | `security:manage` cannot be delegated to keys (X9) |
| Tenant touches another tenant's or the platform's switches | explicit organisation filter + RLS write policy; platform switches read-only (X9) |
| Member probes permissions / floods the log | audited denials with route and permission, 30 per 10 min per principal; metric for the rest (X10) |
| Revoked or expired key still in use | audited in the key's organisation, counted, recommended action (A8) |
| A new endpoint without authentication or tenant checks | OpenAPI-driven API surface suite (X11) |
| Dashboard used to display injected content | summary returns counts; advice has fixed wording |

## 5. Files
* `modules/security_center/` - `models.py` (`audit_verifications`), `integrity.py` (scheduled
  verification and alerts), `posture.py` (signal queries and recommendation rules),
  `service.py` (kill switches, summary, events, manual verification, denial recording),
  `schemas.py`.
* `modules/audit/service.py` - streaming, genesis-anchored `verify_chain`; `security_only` feed.
* `modules/agents/killswitch.py` - real actor and client in the audit, organisation-scoped
  listing and release, duplicate refusal.
* `apps/api/v1/security_center.py`, `apps/api/access.py` (denial hook), `apps/api/problems.py`
  (hook point), `apps/api/middleware.py` (`route_template`: full route templates for metrics and
  audit), `apps/scheduler/main.py` (`security.audit_verification`).
* `infrastructure/db/engine.py` - `snapshot=True` sessions.
* `migrations/versions/0012_security_center.py` - table, RLS, due function, indexes, event types.
* `tests/integration/test_security_center.py`, `tests/security/test_api_surface.py`,
  `tests/unit/test_security_center_units.py`.

## 6. Code worth reading
* `AuditService.verify_chain` - the order of checks matters: sequence, link, hash, then the tail
  against the head; each failure names the first broken sequence number.
* `AuditIntegrity.verify` - "newly broken" is decided against the previous stored result.
* `apps/api/access.py` - membership first, then `request.state`, then the permission check.
* `tests/security/test_api_surface.py` - reads the operation list from `app.openapi()`.

## 7. Tests
* Kill switches: engage/duplicate/validation (unknown agent, tool, provider; `all` needs `*`;
  strict expiry), alerts and e-mail to administrators, real actor in the audit, release twice →
  404; analysts 403; API keys read but never write; another tenant 404 on both paths; platform
  switch shown read-only and not releasable.
* Summary: real signals (denied action, revoked key in use, killed run, tool denials inside and
  outside the window, injection-flagged snapshot, blocked source, model policy block, key
  expiry) counted inside the tenant only; another tenant sees zeros; advice sorted by severity.
* Denials: route permission and service role rule recorded; non-members leave no trace; the
  budget records 30 and counts the rest; the chain stays valid.
* Integrity: manual and scheduled checks; an edited row, the first row deleted, the last row
  deleted and a forged, correctly hashed row behind the head are each detected with the right
  position and reason; one alert per distinct break; manual checks rate-limited.
* API surface (all ~96 operations): anonymous 401 with a challenge; another tenant's owner and
  API key 404; hostile path segments, query values and JSON bodies never cause a 5xx; every
  error is a problem document without internals.

## 8. Common mistakes avoided
* Verifying from "the first row found" (prefix deletion passes).
* Reading the head and the rows in separate snapshots (false alarms under load).
* Recording the alert's audit event in the same transaction as the result (one failure erases
  both).
* Auditing every 403 including non-members' (anyone could write into any tenant's log).
* Free-text in advice or alerts (a reflection channel for injected content).
* FastAPI 0.142 stores routes without their router prefixes: audit and metrics use
  `route_template`, which restores the full template without ever producing an identifier.

## 9. Scalability
Verification is O(chain length) but streams in pages of 1,000 rows with constant memory; the
scheduler verifies a bounded batch per pass (`ARGUS_SECURITY__AUDIT_VERIFY_BATCH`) and spreads
organisations over the day. The summary runs a fixed number of aggregate queries bounded by
organisation and time window; `agent_runs` and `tool_calls` gained `(organization_id,
created_at)` indexes for it. For very large audit logs, incremental verification from a signed
checkpoint is the next step (phase 21).

## 10. Next phases
Phase 20 adds traces and alert rules on top of the counters introduced here
(`argus_audit_verifications_total{result="broken"}`, `argus_access_denied_total`). Phase 23
runs `argus audit verify` for the platform chain as a CronJob and anchors chain heads outside
the database. The phase 24 dashboard renders the security summary.

## 11. Acceptance criteria
* `pytest` (including `tests/security/test_api_surface.py`), `ruff`, `mypy --strict`,
  `lint-imports`, `bandit` green; `argus db check` reports no drift; migration 0012 upgrades
  and downgrades.
* Tampering of each kind is detected by the scheduled job and announced once per break.
* No API key can engage or release a kill switch; no tenant can see or change another's.
* Every non-public operation rejects anonymous calls, and no organisation-scoped operation
  answers another tenant with anything but 404.
