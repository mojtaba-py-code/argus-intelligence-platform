# Phase 17 - Continuous monitoring and notifications

## 1. Purpose
Let an organisation watch what matters - a competitor's pricing page, a product site, the
results of a search - and hear about it only when something meaningful changes. Research jobs
also tell people when they finish, fail or need an approval.

## 2. Architecture
```
scheduler (one leader) ── every minute ──► argus_claim_due_monitors(n)   SECURITY DEFINER:
                                           advances due monitors, returns (org, monitor) ids only
        └─ queue "monitoring" ── monitoring.run ──► MonitorService.execute
              creator re-authorised (tenancy/creators.py) ── revoked? pause + tell admins
              search monitors: queries → search provider → discovered targets (capped)
              per target: SourceService.collect (SSRF guard, robots, politeness, domain policies,
                          injection assessment) → snapshot
                          compare with the monitor's own last snapshot pointer
                          diff with volatile parts removed (dates, "5 minutes ago", counters,
                          copyright years, tokens) → code significance (size, topics, figures)
              strongest changes → MONITOR_ASSESSOR agent (no tools, untrusted input) →
                          final = average of code and model; summary sanitised and defanged
              final ≥ threshold → Event("monitor.change.detected")

research pipeline ── job completed/failed → creator;  approval requested → owners and admins
        │
        ▼
NotificationService (EventSink): current members only → notifications table (in-app)
                                 + plain-text e-mail when the event and settings ask for it

API  /orgs/{org}/projects/{project}/monitors[/{id}[/run|/changes[/{id}/decision]]]
     /orgs/{org}/notifications[/unread-count|/{id}/read|/read-all]
```

## 3. Why this design
* **Collection is not re-implemented.** Monitors fetch through the same `SourceService.collect`
  as research, so every egress rule, robots decision, domain policy and injection check applies.
* **The monitor keeps its own pointer** to the snapshot it last compared, instead of trusting a
  "new content" flag: a page that goes back to an earlier version (A → B → A) is still a change.
* **Noise is removed before comparing**, not after: a page whose only difference is the clock
  produces no diff, so it can never produce an alert.
* **Code scores, a model refines.** Size, watched topics and changed figures give a score in
  code; the monitoring agent's judgement is averaged in. Changes below the floor are never sent
  to a model and never alert.
* **Events decouple producers from channels.** Research and monitoring emit events through a
  small protocol in `core/events.py`; they do not know who is notified or how.
* **Webhooks are not part of this phase.** Outbound integrations were left out deliberately; the
  event protocol is where a future channel would plug in.

## 4. Security
* **Egress**: monitored URLs pass the SSRF URL checks at creation (private addresses, internal
  names, other schemes and ports are refused) and the guarded fetcher on every run.
* **Acting for the creator**: every run re-authorises the creator with the request-time rules
  (API-key scopes, revocation, membership); a creator who lost access pauses the monitor before
  anything is fetched, and owners and administrators are notified.
* **Least privilege**: creating a monitor needs `monitors:manage`, `sources:manage` and
  `sources:read` (it adds pages to the project's sources); reading needs `monitors:read`.
* **Untrusted page text** reaches the monitoring agent only as delimited data; the agent has no
  tools. Summaries and diff excerpts are sanitised and URL-defanged; a summary that reads as an
  instruction is replaced by "The page changed (content withheld).".
* **Notifications** are plain text; links are application paths only (never external URLs);
  recipients are re-checked against current membership; a user's notifications are invisible to
  everyone else, and a service-account key has no inbox. E-mails are plain text.
* **Cross-tenant scheduler work** goes through two narrow `SECURITY DEFINER` functions that
  return identifiers or a count; the runtime role still cannot read another tenant's rows.
* **Limits**: monitors per organisation, targets and queries per monitor, an interval of at least
  an hour, model-assessed changes per run, manual runs per user per hour; concurrent runs of one
  monitor coalesce in the queue.

## 5. Files
`core/events.py`, `modules/monitoring/{models,diff,assess,schemas,service,tasks}.py`,
`modules/notifications/{models,schemas,service}.py`, `modules/tenancy/creators.py` (shared with
research), `apps/api/v1/{monitors,notifications}.py`, `apps/scheduler/main.py`,
`prompts/monitor.assess/v1.yaml`, `migrations/versions/0011_monitoring_and_notifications.py`.

## 6. Code worth reading
* `monitoring/diff.py` - what counts as a change, and what is only the clock.
* `monitoring/service.py::_check` - fetch, compare with the monitor's own pointer, record.
* `notifications/service.py::_emit` - current members only, plain text, application links.

## 7. Tests
* `tests/unit/test_monitoring_units.py` - noise filtering, real changes, significance, topics,
  the offline assessor, defanged and withheld summaries, score averaging, safe links, request
  validation.
* `tests/integration/test_monitoring.py` - a pricing change alerts (in-app and e-mail) while a
  clock-only change does not; A → B → A is two changes; injected text in a change never reaches
  an alert; the scheduler claims due monitors once; search monitors discover pages; a revoked
  creator pauses the monitor without fetching; permissions and URL validation; notification
  privacy; research jobs notify their creator and approvers.

## 8. Common mistakes avoided
Diffing raw HTML; alerting on timestamps; letting a model decide alone what is significant;
following links found in a changed page; storing alert text with live links; scanning every
tenant's monitors with a privileged runtime role; a monitor that keeps running after its
creator left; e-mails in HTML built from page text.

## 9. Scalability
Dispatch claims batches with `FOR UPDATE SKIP LOCKED`, so several schedulers cannot double-run a
monitor; runs are queue jobs on their own `monitoring` queue and scale with workers; snapshots
are deduplicated by content hash; only the strongest changes per run are sent to a model; read
notifications are purged after the retention period.

## 10. Next phases
Phase 18 links monitored pages and findings to entities in the knowledge graph; phase 19 adds
the remaining security controls and dynamic tests; phase 24's dashboard shows monitors, changes
and notifications.

## 11. Acceptance criteria
- [x] Users create monitors for pages or search queries, with topics, interval and threshold.
- [x] The system periodically collects pages and compares them with previous snapshots.
- [x] Only meaningful changes generate alerts; volatile page parts never do.
- [x] In-app and e-mail notifications are configurable per monitor and safe to display.
- [x] Monitors act with their creator's current rights and pause when those are gone.
