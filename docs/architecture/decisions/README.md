# Architecture Decision Records

Each record is short: the context, the decision, the consequences we accept, and what we rejected.
A decision is changed by writing a new ADR that supersedes the old one - records are never edited
to say something different after the fact.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-modular-monolith.md) | Modular monolith with three process roles | Accepted |
| [0002](0002-tenant-isolation.md) | Tenant isolation: repository filters + PostgreSQL RLS + composite foreign keys | Accepted |
| [0003](0003-postgres-job-queue.md) | Durable job queue in PostgreSQL | Accepted |
| [0004](0004-pgvector-hybrid-retrieval.md) | pgvector + full-text hybrid retrieval with authorisation in SQL | Accepted |
| [0005](0005-token-architecture.md) | EdDSA access tokens, opaque rotating refresh tokens | Accepted |
| [0006](0006-llm-gateway.md) | Provider-agnostic LLM gateway with data governance | Accepted |
| [0007](0007-agent-security-model.md) | Plan-then-execute agents under least privilege | Accepted |
| [0008](0008-ssrf-safe-egress.md) | SSRF-safe egress with DNS pinning | Accepted |
| [0009](0009-document-storage-and-parsing.md) | Encrypted blob storage, sandboxed parsing, API-mediated downloads | Accepted |
