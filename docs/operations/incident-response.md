# Incident response

Detection → alert → containment → investigation → eradication → recovery → post-incident
review (spec §65). This page is the operator's checklist; the alert runbooks are in
[alerts.md](alerts.md).

## 1. Severity and roles

| Severity | Examples | Response |
|---|---|---|
| SEV1 | tenant data exposed to another tenant; audit chain broken; signing or encryption key leaked; active intrusion | page now; incident commander + one investigator; customer communication within 24 h |
| SEV2 | compromised user or API key; prompt-injection campaign steering agents; provider key leaked | same working day |
| SEV3 | probing, blocked SSRF attempts, abuse within limits | next working day |

Roles: **incident commander** (decides, communicates, keeps the timeline), **investigator(s)**,
**scribe**. One person may hold several roles in a small team; the timeline is always written.

## 2. First 15 minutes (any severity)
1. Open an incident record with the time, the alert and the first facts.
2. **Preserve evidence before changing anything**: `argus audit export --chain <org id> --output
   <file>` for each affected organisation and `--chain platform`; store the exports in the
   object-locked bucket. The audit log is append-only in the database, but exports survive a
   compromised database.
3. Contain (section 3) - the smallest step that stops the harm.

## 3. Containment controls

| Need | Control | Who |
|---|---|---|
| Revoke an API key | `DELETE /api/v1/orgs/{org}/api-keys/{id}` (immediate, audited) | organisation admin |
| Block a compromised account everywhere | `argus users disable --email <address> --reason "..."` - sign-in refused, every session revoked, owned API keys refused | operator |
| A user ends their own sessions | `POST /api/v1/auth/logout-all` | the user |
| Stop an agent, tool, provider or model for one organisation | `POST /api/v1/orgs/{org}/security/kill-switches` (takes effect within seconds, all admins alerted) | organisation admin |
| Stop it platform-wide | `argus killswitch engage --kind agent --target analyst --reason "..." --by <you>`; `--kind all --target '*'` stops all AI activity | operator |
| Stop background work | `kubectl -n argus scale deployment/argus-worker --replicas=0` (jobs keep their checkpoints and resume later) | operator |
| Block a malicious source | `PUT /api/v1/orgs/{org}/domain-policies/{domain}` with `{"policy": "block"}` | organisation admin |
| Pause a monitor | `PATCH /api/v1/orgs/{org}/projects/{project}/monitors/{id}` with `{"status": "paused"}` | analyst+ |
| Keep a tenant out entirely | `argus orgs suspend --org <id> --reason "..."` - members get 403, API keys are refused, monitors stop; `argus orgs resume` ends it | operator (owner role; recorded with the reason in the organisation's audit chain) |

## 4. Playbooks

### Leaked API key (SEV2)
Revoke it. Find its use: the organisation's audit log (`api_key.authentication_failed` after
revocation shows continued attempts and their source addresses), traces by `argus.organization.id`.
Issue a new key with the narrowest scopes and an expiry.

### Compromised user account (SEV2, SEV1 if an administrator)
`argus users disable`. Review the organisation's security events (`/security/events`): role
changes, API keys created, kill switches, exports (`report.exported`). Revoke keys the account
created. The user resets their password and re-enrols MFA before `argus users enable`.

### Prompt-injection campaign / agent misbehaving (SEV2)
Kill-switch the affected agent or tool (organisation or platform). Find the sources:
`injection_level = high|medium` snapshots and documents, `agent.tool_denied` events, the agent
runs' tool calls. Block the domains; keep a sample for the evaluation dataset
(`evals/datasets`) so the regression suite covers it. Release the switch when the evaluation
gate passes.

### Suspected cross-tenant exposure (SEV1)
Freeze: scale workers to zero, keep the API up only if the leak path is identified and closed.
The audit log records reads of sensitive data (exports, downloads); compare actors' organisations
with the resources' organisations. Every query runs under row-level security as the runtime role
- a leak means a policy or a SECURITY DEFINER function was bypassed: review recent migrations
first. Notify affected tenants as required by contract and law.

### Audit chain broken (SEV1)
Treat as tampering until proven otherwise ([alerts.md](alerts.md#argusauditchainbroken)). Do not
"fix" the rows. Snapshot the database, export the chain, compare with backups to find what
changed and when, rotate database credentials, review superuser access.

### Leaked platform secret (SEV1)
* **JWT signing key**: add a new key id to `ARGUS_AUTH__JWT_SIGNING_KEYS`, make it active, roll
  out, then remove the leaked key after the access-token lifetime - every token it signed becomes
  invalid; users sign in again.
* **Encryption key**: add a new key id and make it active (new data); keep the old key for
  decryption until its data is re-encrypted; treat stored data as exposed only if the database or
  bucket was also accessed.
* **Audit HMAC key**: an attacker with it *and* database access can forge chains. The key
  cannot be rotated in place today (one key verifies a whole chain): keep using it, rely on the
  evidence exported and verified before the leak, and restrict database access until a re-keyed
  chain epoch exists (listed as a residual risk in the threat model).
* **Model or search provider key**: revoke at the provider, update the secret, restart.

## 5. Eradication and recovery
Remove the cause (fix and release through CI - never patch production by hand), restore damaged
data from point-in-time recovery ([backup-restore.md](backup-restore.md)), release containment
step by step while watching the alerts that fired.

## 6. Post-incident review (within 5 working days)
Blameless: timeline, impact, what detected it and how fast, what contained it, what slowed us
down. Every action item gets an owner and a date; threats become entries in
[../security/threat-model.md](../security/threat-model.md) with a test in the security suite.
