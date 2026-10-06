# Phase 3 - Multi-tenant core

## 1. Purpose
Turn authenticated users into members of organisations with roles, give organisations projects,
service accounts and API keys, and make it *structurally impossible* for one tenant to read or
write another tenant's data.

## 2. Architecture
```
request ─▶ authenticate (JWT or API key) ─▶ Authorizer.org/project(principal, ids, permission)
          │                                   ├ membership / service-account role (RLS context = org)
          │                                   ├ role permissions ∩ API-key scopes
          │                                   ├ org policy (suspended? MFA required?)
          │                                   └ restricted project? project role required
          ▼
   OrgAccess / ProjectAccess (TenantScope) ─▶ service ─▶ Database.tenant(scope) ─▶ RLS
```

## 3. Why
Shared schema + RLS scales to thousands of tenants with one migration path; three independent
layers (query filters, RLS, composite FKs) mean a single bug cannot leak data (ADR 0002).

## 4. Security considerations
| Threat | Control |
|---|---|
| IDOR across tenants (T1) | foreign ids → 404; RLS; tested for 13 endpoints with session *and* API-key credentials |
| Forgotten `WHERE organization_id` (T5) | RLS fails closed: no context → zero rows (tested on 5 tables) |
| Malformed/forged context | `NULLIF(...)::uuid` raises on garbage (tested with an injection-shaped value) |
| Cross-tenant references (T3) | composite FKs `(organization_id, project_id)`, `(organization_id, user_id)` |
| Role escalation (T2) | only owners grant/remove owner; nobody edits their own role; last owner protected; invite ≤ own role |
| Over-powered API keys (A8) | scopes ⊆ owner's role at creation *and* scopes ∩ current role at use; dangerous scopes never delegable |
| Invitation hijack | invitation bound to the invited, verified e-mail address |
| Key verification leaking hashes | `argus_authenticate_api_key(key_id, hash)` compares inside PostgreSQL and returns a row only on match |
| Platform admins browsing tenant data | no implicit tenant access (privacy by design) |

## 5. Files
`modules/tenancy/{models,schemas,authorization,service,projects,api_keys}.py`,
`apps/api/{access.py, v1/orgs.py, v1/projects.py}`, `migrations/versions/0003_tenancy.py`,
`core/classification.py`.

## 6. Code worth reading
* `Authorizer.org` - the whole policy in ~60 lines; deny by default, 404 before 403.
* Migration 0003 - RLS policy text, the membership-aware `member_read` policy on organisations, and
  the two SECURITY DEFINER functions with a pinned `search_path`.
* `ApiKeyService.create` - the key's scopes may never exceed its owner's *current* permissions.

## 7. Tests
`tests/integration/test_tenancy.py` (flows and rules) and `tests/integration/test_tenant_isolation.py`
(the three layers attacked directly: HTTP with both credential types, raw SQL as the runtime role,
cross-tenant inserts, forged context, FK smuggling).

## 8. Common mistakes avoided
403 for foreign resources (confirms existence); checking membership in the UI only; an
`is_admin` flag that bypasses tenant filters; API keys with static permissions that survive the
owner's demotion; storing API keys in plaintext; listing endpoints without keyset pagination.

## 9. Scalability
Authorisation costs two indexed lookups per request (membership + project). RLS predicates use
`STABLE` functions evaluated once per statement. All listing queries use `(organization_id,
created_at)` indexes with keyset pagination.

## 10. Next phase
Phase 4 creates research jobs inside projects (`ProjectAccess`) and runs them asynchronously in
workers that re-enter the tenant context from the job's organisation id.

## 11. Acceptance criteria
- [x] 13 foreign-tenant endpoints answer 404 for sessions and API keys.
- [x] Without tenant context the runtime role sees zero rows; with context only its own tenant.
- [x] Cross-tenant INSERT fails with an RLS violation; cross-tenant UPDATE/DELETE affect 0 rows.
- [x] Composite FKs reject cross-tenant project memberships.
- [x] API keys follow their owner's demotion immediately; revoked/disabled keys stop at once.
