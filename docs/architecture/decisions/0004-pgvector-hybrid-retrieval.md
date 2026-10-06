# ADR 0004 - pgvector + full-text hybrid retrieval with authorisation in SQL

**Context.** Semantic search must never return a chunk the caller cannot access, and deleting a
document must remove its searchable representation. With an external vector database these are
two systems that must agree.

**Decision.** Chunks, their embeddings (`vector(N)`, HNSW cosine index) and their `tsvector` (GIN
index) live in one table. One SQL statement runs the vector and keyword candidate searches inside
the **authorised scope** (organisation, projects the principal may read, classification ceiling,
embedding model) and fuses them with Reciprocal Rank Fusion (k = 60). Authorisation happens in the
`WHERE` clause and again in RLS - never after retrieval, and never by the LLM.

**Consequences.** Deletion is a cascading delete in one transaction. Filtered HNSW search on
pgvector < 0.8 can under-fill results for a small tenant among large ones; the retriever enables
`hnsw.iterative_scan` when the server supports it and over-fetches otherwise.

**Rejected.** An external vector DB as the source of truth (dual writes, a separate auth model);
post-filtering results in Python (wastes the top-k and leaks through timing).
