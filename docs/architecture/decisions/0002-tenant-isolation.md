# ADR 0002 - Tenant isolation in three independent layers

**Context.** A user from organisation A must never read organisation B's documents, reports,
prompts, embeddings or keys. A single missed `WHERE organization_id = ...` is the most common way
multi-tenant SaaS products leak data.

**Decision.** Shared database, shared schema, `organization_id` on every tenant-owned table, and
three layers that each stop a leak on their own:

1. **Repository layer** - every query is built from a `TenantScope`; tenant repositories have no
   method that can run without one.
2. **PostgreSQL Row-Level Security** - the runtime role (`argus_app`) is not the table owner and
   has no `BYPASSRLS`; policies compare `organization_id` with the transaction-local setting
   `argus.org_id`, written with `set_config(..., true)` at the start of every unit of work.
   An unset context matches no rows (fail closed).
3. **Composite foreign keys** - child tables reference `(organization_id, id)` of their parent,
   so a row can never point at another tenant's project or document, even through a bug that
   bypasses the first two layers on insert.

Cross-tenant system work (claiming queue jobs, finding due monitors, authenticating an API key
before the tenant is known) goes through narrowly scoped `SECURITY DEFINER` functions owned by the
schema owner that return only what the caller needs.

**Consequences.** Isolation holds even for raw SQL written in a hurry. Integration tests run as the
runtime role against real PostgreSQL to prove it. Cost: every insert must carry the tenant id, and
`INSERT ... RETURNING` is subject to the SELECT policy (handled by the unit of work setting the
context before any statement).

**Rejected.** Database-per-tenant (operationally heavy at thousands of tenants; kept as an option
for regulated customers); schema-per-tenant (migration fan-out); application-only filtering (one
bug away from a breach).
