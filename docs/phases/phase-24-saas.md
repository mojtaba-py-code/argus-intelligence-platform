# Phase 24 - SaaS architecture

## 1. Purpose
Run Argus as a service many organisations share, safely and fairly: plans with limits that hold
under concurrency, usage people can see, the retention settings organisations choose actually
enforced, an organisation lifecycle (suspension, deletion with a grace period, restore, purge),
a complete data export for owners, platform administration for operators - and the web
dashboard of spec §53, which shows all of it.

Self-hosted installations change nothing: new organisations start on the `enterprise` plan (no
quotas). A hosted service sets `ARGUS_PLATFORM__DEFAULT_PLAN=free` and upgrades organisations with
`argus orgs set-plan`.

## 2. Architecture
```
argus.modules.platform
  plans.py       the plan catalogue (code): free / team / business / enterprise
  quotas.py      usage per metric, enforce() inside the creating transaction, usage report
  retention.py   daily sweep: each organisation in its own row-level-security context
  lifecycle.py   plan changes, suspend / resume / restore, purge (operator and scheduled)
  exports.py     owner-only ZIP export: one snapshot, explicit columns, sealed storage, expiry
  dashboard.py   one overview request, filtered by what the viewer may see
  tasks.py       the export worker task
argus.apps.api.v1.platform   GET  /orgs/{id}/usage          (usage:read)
                             GET  /orgs/{id}/dashboard      (org:read; costs need usage:read,
                                                             security events need audit:read)
                             POST/GET /orgs/{id}/exports, GET .../exports/{id}/download (org:export)
argus.apps.web               /app: index.html + app.js + app.css + icon.svg, own CSP; / -> /app/
argus.apps.cli               argus orgs list|suspend|resume|restore|set-plan|purge
                             argus audit prune --chain --older-than-days
scheduler                    platform.retention (daily), platform.purge_organizations (hourly)
migration 0014               plan CHECK, audit_checkpoints, argus_prune_audit, organization_exports
                             (RLS), two listing functions, monitors of inactive organisations skipped
```

Plans (`None` = unlimited):

| Plan | Members (incl. open invitations) | Projects | Monitors | API keys | Research jobs / month | Storage | Model budget ceiling / month |
|---|---|---|---|---|---|---|---|
| free | 5 | 3 | 3 | 5 | 50 | 1 GiB | $25 |
| team | 25 | 25 | 25 | 25 | 1,000 | 25 GiB | $500 |
| business | 200 | 200 | 200 | 100 | 10,000 | 250 GiB | $5,000 |
| enterprise | - | - | - | - | - | - | organisation's own budget |

## 3. Why this design
* **Plans are code, like the permission matrix.** A limit changes by review, not by an UPDATE
  someone forgot. The database stores only the plan's name (CHECK over the catalogue); an
  unknown name - an operator typo - is treated as `free`: quotas fail closed.
* **A quota is checked where the row is written.** `quotas.enforce` counts inside the same
  transaction as the insert, under a transaction advisory lock per organisation and metric. A
  check in a separate request (or before the transaction) lets four concurrent requests all see
  "2 of 3" and create five projects; the integration test sends exactly that race and gets one
  201 and three 403s. The lock is per organisation and metric, so tenants never wait for each
  other.
* **Seats include invitations, storage includes the upload.** An invitation is a promise of a
  seat (re-sending one replaces the open invitation, so it needs no extra seat); an upload is
  counted with its own size before it is stored.
* **The budget ceiling is enforced twice.** Raising the organisation's model budget above the
  plan's ceiling is refused (422), and the gateway's ledger uses `min(organisation budget, plan
  ceiling)` - so a plan downgrade takes effect even for a budget set earlier.
* **Retention deletes what the settings say, and nothing the product still needs.** Superseded
  versions of a web page are deleted, never the current one (the knowledge base answers from it)
  and never one a monitor compares against; their chunks, vectors and citations follow through
  foreign keys. "Current" means *seen most recently*: when a page changes back to content it had
  before, the earlier version's row is reused, so the newest `fetched_at` is not the current
  page - the review that caught this is in phase 25. Monitor changes, per-call model ledger rows (daily aggregates stay for budgets),
  expired exports with their archives and finished queue jobs go too. Uploaded documents are
  customer data: they stay until someone deletes them.
* **Audit events can expire without breaking verification.** The chain is verified from its
  genesis, so deleting old rows would look exactly like tampering. Pruning therefore writes a
  *signed checkpoint* (an HMAC over chain, sequence and hash, with the audit key that never
  enters the database) and the verifier starts from it. The database itself enforces the rules:
  only `argus_prune_audit` can delete audit rows (the append-only trigger allows a DELETE only for
  the schema owner with a transaction-local flag that function sets), never rows younger than 90
  days, only behind a checkpoint whose anchor row matches, an organisation only its own chain,
  the platform chain only the owner role - and the service refuses to prune a chain that does not
  verify. A forged checkpoint is reported as `checkpoint forged`. Pruning frees the sequence
  numbers below the checkpoint, and verification starts above it, so a trigger refuses any new
  row at or below a checkpoint, and verification reports one that got there anyway (`rows below
  the checkpoint`). Checkpoints are readable by the runtime role only for its own organisation.
  `argus audit prune` never keeps less than the chain is owed: the organisation's own
  `retention.audit_days`, or `platform.platform_audit_retention_days` for the platform chain.
* **Lifecycle states are enforced at every entrance.** `suspended`: members get 403, API keys
  are refused, monitors are no longer claimed. `pending_deletion` (an owner deletes): access ends
  at once, API keys are revoked, and the data waits `deletion_grace_days` (30) so an operator
  can restore it. The purge first marks the organisation `purging` in its own transaction - the
  point of no return: a restore racing with it waits for the row lock and then finds nothing to
  restore, so an organisation can never come back with half of its files deleted - then deletes
  the stored blobs and the organisation row (every tenant table follows through same-tenant
  foreign keys) and records `org.purged` in the platform chain. A purge interrupted half-way is
  finished by the next scheduled run. Access checks accept only `active` and `suspended`: any
  other state, including one added later, fails closed. The organisation's audit history is
  kept: it outlives the tenant on purpose.
* **An export is the organisation's data and nothing else.** Only owners (`org:export`, never
  delegable to an API key) request it; a worker builds it in one REPEATABLE READ snapshot inside
  the organisation's row-level-security context, so it is consistent and cannot contain another
  tenant's rows. Tables are exported with explicit column lists: no password, key or token
  hashes, no MFA secrets, no embeddings. Entry names are generated from ids and a sanitised file
  name, so extracting the archive cannot write outside its folder. Only documents a member could
  download are included - never quarantined or unscanned files - and a damaged or missing file is
  listed in the manifest instead of failing the whole export. The archive is sealed (AES-GCM)
  like documents, its SHA-256 is checked before each download, and it expires after 7 days. The
  requester must still be an owner when the worker builds it and when it is downloaded; requests
  (3 per day, one in preparation at a time - a unique index, so concurrent requests cannot both
  start one), downloads (10 per hour) and both events are audited. Memory is bounded: included
  documents are capped (128 MiB by default, at most 1 GiB), the archive stays below the
  single-object encryption limit, and an API process decrypts at most two archives at once. The
  manifest carries the chain's verification and, for a pruned chain, the signed checkpoint it
  starts from, so the copy can be re-verified offline (so does `argus audit export`).
* **The dashboard is one request, filtered like everything else.** `/dashboard` applies the
  authoriser's project-visibility rule (restricted projects only for their members, owners and
  admins) and the permission of the endpoint behind each section: projects need
  `projects:read`, jobs `research:read`, reports `reports:read`, sources `sources:read`, the
  knowledge base `documents:read`, monitoring `monitors:read`, costs `usage:read`, security
  signals `audit:read`. A section the viewer cannot read is `null` - so an API key scoped to
  `org:read` learns no project or report title through the aggregate either. It is read in one
  snapshot, and every list is bounded (8 items).
* **The web dashboard is a client of the public API, nothing more.** No server-side rendering,
  no session cookie, no special endpoint: the same bearer tokens, authorisation and audit trail
  as any client. It is served from four allow-listed files with its own Content-Security-Policy.
  Its session logic follows a few strict rules: signing out clears the page *before* telling the
  server; every sign-out starts a new epoch, so a late answer (a refresh, an overview, an error)
  for a previous session, organisation or report is dropped instead of reviving or overwriting
  anything; a page kept in the browser's back/forward cache comes back signed out; polling
  leaves an unchanged page (and keyboard focus) alone.

## 4. Security
| Threat | Mitigation |
|---|---|
| Concurrent requests overrun a plan limit | count + insert in one transaction under an advisory lock per organisation and metric |
| An organisation lifts its own model budget | budget updates above the plan's ceiling refused; effective budget capped at spend time |
| An export leaks another tenant's rows, secrets or internals | RLS context + one snapshot; explicit columns; owner-only permission re-checked at build and download |
| A crafted file name escapes the export folder on extraction | generated entry names; a test asserts no absolute or `..` entries |
| A tampered or stale archive is served | sealed storage bound to the key; SHA-256 checked; expiry deletes the blob |
| Retention is used to erase evidence, or breaks audit verification | DB-enforced pruning rules (owner only, 90-day floor, signed checkpoint, own chain only); chain must verify first; forged checkpoints detected |
| A suspended or deleted organisation keeps working through keys, monitors or the dashboard | only `active` (and, with 403, `suspended`) passes any entrance; keys refused and revoked; monitors not claimed |
| An organisation is restored while its purge is deleting files | `purging` is committed before any file is touched and cannot be restored; an interrupted purge is resumed |
| A narrowly scoped API key reads titles through the dashboard aggregate | each section requires the permission of its own endpoint |
| Quarantined files leave through an export | only downloadable documents are exported |
| Forged audit rows below a checkpoint | insert trigger refuses them; verification reports them |
| XSS in the dashboard steals tokens (report titles, monitor summaries and source URLs come from untrusted pages) | text-only rendering; CSP with no inline code, same-origin only and Trusted Types (`require-trusted-types-for 'script'`, no policies); tokens in memory only; idle sign-out after 30 minutes; sign-out on tab close |
| A signed-out dashboard comes back (late token refresh, back/forward cache) or shows another organisation's data | session epochs drop late answers; the page clears itself on `pagehide` when the browser keeps it |
| Clickjacking, CSRF, referrer leaks | `frame-ancestors 'none'` and `X-Frame-Options: DENY`; bearer tokens, never cookies; `no-referrer`; source links `noopener noreferrer nofollow`, http(s) only |
| Routes outside the OpenAPI document escape the security suite | a reviewed list of undocumented routes, enforced by a test |

The dashboard's CSP:
```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self';
base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none';
require-trusted-types-for 'script'; trusted-types 'none'
```
`form-action 'none'` matters: the sign-in form is submitted by the script; if the script fails to
load, the browser refuses to submit the form natively, so a password can never end up in a URL.

## 5. Files
`src/argus/modules/platform/` (plans, quotas, retention, lifecycle, exports, dashboard, tasks,
models), `src/argus/apps/api/v1/platform.py`, `src/argus/apps/web/` (router and `static/`),
`src/argus/apps/api/middleware.py` (`WEB_CSP`), `src/argus/apps/cli/main.py` (`orgs`,
`audit prune`), `src/argus/apps/scheduler/main.py`, `src/argus/modules/audit/service.py`
(`prune`, checkpoint-aware `verify_chain`), `src/argus/modules/audit/models.py`
(`AuditCheckpoint`), `migrations/versions/0014_saas_platform.py`, quota calls in the tenancy,
research, documents and monitoring services, `scripts/seed_demo.py`.

## 6. Code worth reading
* `quotas.enforce` - the count and the advisory lock, and why both live in the caller's
  transaction.
* `argus_reject_modification` and `argus_prune_audit` in migration 0014 - how the database
  allows exactly one kind of audit deletion.
* `AuditService.verify_chain` - streaming verification that starts at a checkpoint and checks its
  signature.
* `retention._EXPIRED_EXPORTS` - `RETURNING` returns the *updated* row, so the archive key is read
  from the locked old row (the test caught the first version, which never deleted archives).
* `ExportService._archive` - one snapshot, explicit columns, generated names.
* `static/app.js`: `request()` (same origin, no cookies, no redirects, one retry after a single
  shared refresh), `refreshTokens()` (one refresh at a time: refresh tokens rotate, and the
  server treats a reused one as theft; a refresh that answers after a sign-out is dropped),
  `signOut()` (the page forgets first) and `load()` (answers for another epoch or organisation
  are dropped).
* `OrganizationLifecycle.purge` - the `purging` state as a point of no return.

## 7. Tests
`tests/integration/test_platform.py`: free-plan quotas enforced and reported (projects, API keys,
seats with invitations, the budget ceiling); a four-way race for the last slot; research-job and
storage quotas; retention keeps the current page version, deletes superseded ones, old ledger rows
and audit events behind a checkpoint, and the chain still verifies and keeps growing; a forged
checkpoint is detected; the database refuses unsafe pruning (too young, another chain, the
platform chain from the runtime role, a wrong hash, a plain DELETE); the sweep covers every
organisation; suspension, deletion, restore and purge (blobs gone, audit kept, `org.purged`
recorded; a purge that dies half-way cannot be restored, hides the organisation and is finished
by the next run); exports (owners only, one pending at a time even under concurrent requests,
content complete, no other tenant, no internals, safe names, no quarantined file, a damaged file
listed instead of failing, download slots, expiry deletes the archive); a failed build is retried
and a lost one stops blocking after three hours; retention keeps a page version that came back;
no audit row can be added below a checkpoint and one smuggled there is reported; `argus audit
prune` refuses less than the chain is owed and unknown chains; re-sending an invitation at full
capacity works; the dashboard shows each viewer - and each API key - only what they may see.

`tests/unit/test_web_dashboard.py`: only the allow-listed files ship; the script has no HTML
sinks, no code from strings, no storage, no other channels or origins; anchors only through the
scheme check; every element the script uses exists; no inline script, style or handler in the
page; forms cannot submit secrets in a URL; the stylesheet and icon load nothing; the CSP and
headers on `/app`; nothing else reachable (`..`, case, the index under a second name); the API
keeps its stricter policy; `If-None-Match` compared weakly; the dashboard can be switched off
(`ARGUS_HTTP__WEB_DASHBOARD=false`).

`tests/web/dashboard.test.mjs` (run by the unit suite when Node.js is installed): the script itself,
against the real page in a small fake DOM with a scripted API and virtual time - sign-in, a
failed sign-in (password cleared, focus back), sign-out before the server answers, one refresh at
a time and no revival after sign-out, the back/forward cache, answers for a previous organisation
or report dropped, idle sign-out, focus kept while polling, sections the viewer may not read.

`tests/unit/test_api_foundation.py`: every route outside the OpenAPI document is in a reviewed
list.

**Try it locally:** with a development database and keys in `.env`, run
`python scripts/seed_demo.py` (a demo organisation: three documents, a real research report from
the offline models, a queued job, a monitor with a detected change), then `argus serve` and open
http://localhost:8000/ - the credentials are written to `.env.demo` (git-ignored).

## 8. Common mistakes avoided
* Check-then-insert quotas: correct in every test that runs one request at a time, wrong in
  production.
* `UPDATE ... SET key = NULL RETURNING key` returns NULL: archives would have stayed in storage
  forever while their rows said "expired".
* Marking a job's record failed on the first error: the queue retried, found "failed" and
  skipped - a retry that never retries. Only the final attempt records the failure now.
* A "pending" record that only its worker can finish blocks forever when the worker dies; now
  a pending export older than three hours no longer blocks a new one.
* Taking "newest fetched" for "current": content that comes back reuses its old row.
* An aggregate endpoint that checks only `org:read` while each detail endpoint checks more.
* A purge that can be undone half-way, leaving an organisation whose files are gone.
* Async answers applied to whatever is on screen when they arrive.
* Deleting old audit rows, then wondering why verification fails - or skipping verification
  because it fails.
* Tokens in `localStorage` (readable by any script on the origin, kept after sign-out) and
  `innerHTML` with API data (titles of web pages are attacker-controlled).
* An unknown plan name meaning "no limits".

## 9. Scalability
Quota counts use per-organisation indexes and are bounded by the plan's limits; locks are per
organisation and metric. Retention deletes in batches of 1,000 rows per transaction, one
organisation at a time, so it never holds long locks; organisations are listed 200 at a time by
a function that returns ids and retention settings only. Exports are written to a temporary file
(not memory), with a total cap on included documents; one pending export per organisation and
the daily limit bound the work. The dashboard is a fixed set of indexed aggregate queries in one
read-only transaction; the web client polls once a minute and only while the tab is visible.

## 10. Next phases
Phase 25 reviews the whole system against the threat model, runs the complete test suite and
static checks, and completes the documentation.

## 11. Acceptance criteria
* No sequence of concurrent requests creates more than a plan allows.
* Retention runs daily, deletes only what the settings allow, and the audit chain verifies before
  and after pruning; the database refuses every other way to delete audit rows.
* Suspended and deleted organisations lose access at once; deletion can be undone within the
  grace period; a purge leaves no tenant rows or blobs, and the audit history remains.
* An owner can export everything the organisation owns, and the archive contains nothing else.
* The dashboard shows the eleven areas of spec §53, each only to members allowed to see it, under
  a CSP that allows no inline code and enforces Trusted Types.
