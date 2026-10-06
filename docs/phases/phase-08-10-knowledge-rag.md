# Phases 8-10 - Knowledge store, embeddings, retrieval-augmented generation

## 1. Purpose
Turn every parsed document and collected web page into *searchable evidence* - and make it
impossible for search to return anything the caller may not read. Phase 8 stores chunks in
PostgreSQL, phase 9 embeds them and adds vector search, phase 10 fuses keyword and vector
search, reranks, and packs evidence for a model with the provenance a citation needs.

## 2. Architecture
```
document ready / page collected
  └─ chunk (paragraph → sentence → word-boundary windows; exact char offsets; PDF pages)
  └─ may this text go to the embedding provider?  classification ≤ org policy[provider locality]
        yes → embed in batches (outside any transaction)      no → keyword-searchable only
  └─ one transaction: replace the parent's chunks + bump projects.corpus_version

search(query) for a principal
  └─ scope = organisation + project + classification ceiling + origins allowed by permissions
  └─ cache? key = scope + corpus versions + query + model (AES-GCM encrypted entries)
  └─ ONE SQL statement:  vector top-k (HNSW, cosine)  ∪  keyword top-k (GIN, any term)
                          both inside the scope's WHERE  → Reciprocal Rank Fusion (k = 60)
  └─ rerank (lexical, or Voyage if the policy allows) → ≤ 3 chunks per document → top n
  └─ pack_evidence: nonce-delimited blocks with source, page, title; token budget
```

## 3. Why these technologies
* **pgvector in the same database** (ADR 0004): one transaction deletes a document and its
  vectors; one statement applies authorisation to both searches; RLS covers vectors too.
* **HNSW** for approximate nearest-neighbour search (no training step, good recall); on
  pgvector ≥ 0.8 the retriever enables iterative scans so selective filters cannot starve the
  top-k, on older versions it over-fetches.
* **A PostgreSQL-generated `tsvector`** (English stemming for English text, language-neutral
  tokenisation otherwise - Persian included) so the application cannot forget to update it.
* **Reciprocal Rank Fusion**: rank-based, so the incomparable scores of cosine distance and
  `ts_rank_cd` never need calibrating.
* **A deterministic local embedder** (`argus-hash-v1`, feature hashing of words, bigrams and
  character trigrams): the platform works offline, tests are reproducible, and the evaluation
  measures exactly what it is worth. **Voyage** (`voyage-4`) is the drop-in semantic option.

## 4. Security considerations
* **Authorisation before retrieval** (threat R1): the scope is computed from permissions and
  becomes the query's `WHERE` clause; RLS applies on top; the model never sees out-of-scope
  text and is never asked to filter. Restricted content needs `documents:read_restricted`;
  document chunks need `documents:read`, web chunks `sources:read`.
* **Data governance for providers** (R2): text above an organisation's external-processing
  ceiling is never sent to an external embedder or reranker; it stays findable by keywords.
  Queries are treated as internal data.
* **Poisoned content** (R3): each chunk carries the stricter of its own injection level and its
  parent's (a document that hid instructions anywhere is trusted nowhere); high-risk chunks are
  indexed for review but excluded from retrieval by default.
* **Evidence packing**: blocks are delimited with a random per-pack nonce the text cannot know,
  and delimiter look-alikes inside the text are neutralised.
* **Caches** (R4): keyed by scope *and* corpus versions, encrypted with the keyring, short TTL.
* **Deletion** (R5): chunks cascade in the deletion transaction; caches are invalidated by the
  version bump.
* **Provider responses are untrusted**: embedding count, indexes, dimensions and finiteness are
  validated; 429/5xx are retried with jitter and `Retry-After`; an outage during search degrades
  to keyword search, during indexing it retries the job from the indexing step (no re-parse).

## 5. Files
`modules/knowledge/{chunking,models,indexing,retrieval,context,schemas,service}.py`,
`modules/llm/{embeddings,voyage,governance}.py`, `modules/tenancy/corpus.py`,
`apps/api/v1/knowledge.py`, `migrations/versions/0007_knowledge_chunks.py`.

## 6. Code worth reading
* `retrieval.py::_candidates` - the whole hybrid search, authorisation included, in one statement.
* `indexing.py::_index` - the governance decision, embedding outside the transaction, and the
  replace-and-version-bump transaction.
* `chunking.py::chunk_text` - exact offsets, page mapping and boundary-aligned overlap in linear time.

## 7. Tests
* `tests/unit/test_knowledge_units.py` - chunk offsets/pages/overlap/edge cases, embedder
  determinism and similarity, the Voyage client (request shape, reordering, retries, malformed
  responses), data-policy ceilings, reranking, cache round trip, evidence nonces and budgets.
* `tests/integration/test_knowledge.py` - documents and web pages become searchable with
  provenance (file, URL, page); search modes and validation; authorisation (restricted content,
  other projects, other tenants, origins by API-key scope); injected documents excluded;
  deletion; encrypted cache with version invalidation; the external-embedder data policy;
  retry-from-indexing without re-parsing; and a retrieval-quality evaluation.

**Evaluation** (10 documents, 12 queries incl. typos and Persian, top 3, local embedder; every
mode goes through the same lexical reranker and per-document cap):

| method | MRR | recall@3 |
|---|---|---|
| keyword only (any term, cover density) | 0.92 | 0.92 |
| vector only (`argus-hash-v1`) | 1.00 | 1.00 |
| **hybrid (RRF + lexical rerank)** | **1.00** | **1.00** |

Keyword search with all-terms (web-search) semantics scored 0.58 on the same set, which is why
keyword *candidates* use any-term matching: fusion and reranking supply the precision. The corpus
is deliberately small; phase 16 adds a larger evaluation set and a regression gate.

## 8. Common mistakes avoided
Filtering after vector search (leaks through timing and starves top-k); a separate vector
database with its own permissions; embedding restricted text with a SaaS model; trusting the
model to respect permissions; caching by query only; zero-overlap or mid-word chunking;
re-parsing a document because an embedding API timed out.

## 9. Scalability
HNSW + GIN indexes; candidate sets bounded by `retrieval.candidates`; batch embeddings; caches
per organisation; corpus versions avoid cache scans. Very large tenants can move to partitioned
chunk tables or a dedicated retrieval replica without changing the scope logic.

## 10. Next phases
Phase 11 routes generation through the gateway under the same data policy; phases 12-14 give
agents a `search_documents`/`query_knowledge` tool that calls `KnowledgeService.scope_for` and the
retriever; phase 15 verifies that each citation's quote is present in the cited chunk.

## 11. Acceptance criteria
- [x] Retrieval never returns another tenant's, another project's or a restricted chunk to a
      caller without the permission - proven as the runtime role.
- [x] Text above the external ceiling never reaches an external provider.
- [x] Deleting a document removes its chunks and vectors in the same transaction.
- [x] Hybrid search is at least as good as either method on the evaluation set.
- [x] Results carry provenance (document/file, URL, page, character range) for citations.
