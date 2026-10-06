# Phase 23 - Production deployment

## 1. Purpose
Run Argus on Kubernetes with the same security posture it has in code: least privilege for
every process, a network that enforces what the application enforces, zero-downtime releases of
signed images only - and written procedures for deploying, restoring and responding to
incidents, backed by the tools those procedures call.

## 2. Architecture
```
namespace argus (Pod Security "restricted" enforced)
  argus-api        Deployment + Service + HPA (2-10) + PDB   readiness = DB at/ahead of head
  argus-worker     Deployment + HPA (2-20) + PDB             waits for the schema; /metrics :9100
  argus-scheduler  Deployment (2, one leader)                waits for the schema; /metrics :9100
  argus-migrate    Job       (owner DSN)                     once per release
  argus-audit-verify CronJob (owner DSN)                     daily, every chain incl. platform
  NetworkPolicies: default deny; DNS; ingress controller -> api:8000; monitoring -> :8000/:9100;
                   data services on 5432/6379/6380 (private ranges); clamd; OTLP collector;
                   api+worker -> internet 443/587 and worker -> 80, never private, link-local
                   (cloud metadata) or CGNAT ranges
Secrets: argus-runtime (no schema owner)  ·  argus-owner (Job and CronJob only)
overlays/staging, overlays/production: signed digest, https endpoints, replica floors
```

## 3. Decisions and the fixes they surfaced
* **Owner credentials only where needed.** The production configuration check used to require
  the schema owner's DSN in *every* process, so API pods would have held credentials able to alter
  the schema. Runtime processes now run without it; operator commands (`db migrate`, `audit`,
  `killswitch`) require it explicitly in production, and only the migration Job and the audit
  CronJob receive the `argus-owner` Secret (a test enforces this).
* **Zero-downtime migrations.** Readiness used to require the database to be *exactly* at the
  image's migration head: the moment a release's migration finished, every old API pod would
  have turned unready. Readiness now accepts a schema at or ahead of the image's head (migrations
  stay backward compatible for one release) and only refuses one that is behind. Workers and the
  scheduler, which have no readiness gate, wait for the schema before claiming any job.
* **The network repeats the SSRF rules.** Internet egress excludes private, link-local (cloud
  metadata) and CGNAT ranges, and only the API and workers have it at all: a bug in the
  application's guard is not enough to reach internal services.
* **Containment tools for operators.** `argus users disable` blocks a compromised account in one
  step (sign-in, every session in the database and the shared cache, and the API keys it owns);
  `argus audit export` writes a self-contained, re-verifiable evidence copy of a chain.
* **Overlays are the record of what runs.** They pin the image by digest after `cosign verify`;
  the placeholder digest never resolves, so an unpinned overlay cannot deploy.

## 4. Security
| Threat | Control |
|---|---|
| A compromised pod escalates on its node | Pod Security `restricted` enforced on the namespace: non-root, no privilege escalation, every capability dropped, `RuntimeDefault` seccomp, read-only root filesystem; no service-account token mounted |
| A compromised API pod alters the schema or the audit history | runtime pods hold the runtime role only; the owner role exists only in the migration Job and the audit CronJob |
| SSRF reaches internal services or cloud metadata despite the application guard | default-deny NetworkPolicies; internet egress for the API and workers only, excluding private, link-local and CGNAT ranges |
| A tampered or unexpected image runs | overlays pin a digest that was verified with `cosign verify` against the release workflow identity |
| A release takes the service down | readiness accepts a schema at or ahead of the image's head; rolling updates with `maxUnavailable: 0`; PodDisruptionBudgets |
| Lost data or an unprovable incident | backups with restore drills and stated RPO/RTO; `argus audit export` evidence copies; account containment with one command |

## 5. Runbooks
[deployment.md](../operations/deployment.md) · [backup-restore.md](../operations/backup-restore.md) ·
[incident-response.md](../operations/incident-response.md) ·
[disaster-recovery.md](../operations/disaster-recovery.md) · [alerts.md](../operations/alerts.md)

## 6. Files
`deploy/kubernetes/{base,overlays,components}`, `deploy/kubernetes/secrets.example.yaml`,
`src/argus/infrastructure/db/migrations.py` (`schema_state`), `src/argus/apps/process.py`
(`wait_for_schema`), `src/argus/modules/identity/administration.py`, `src/argus/apps/cli/main.py`
(`users disable|enable`, `audit export`, owner-DSN checks), `src/argus/core/config.py`.

## 7. Tests
`tests/unit/test_kubernetes_policy.py` (restricted profile on every workload, owner Secret only
in operator jobs, probes and graceful shutdown, default-deny networking without internal ranges,
pinned https overlays, placeholder-only secret template); CI renders both overlays and validates
them with kubeconform (checksum-verified download); `tests/integration/test_operations.py`
(account containment, evidence export, schema wait); `tests/unit/test_api_foundation.py`
(readiness across schema versions); `tests/unit/test_config.py` (runtime without owner DSN).

## 8. Common mistakes avoided
* One Secret with every credential, mounted everywhere "for convenience".
* A readiness probe that turns every old pod unready the moment a migration finishes.
* Network policies that allow "the internet" as `0.0.0.0/0` - which includes the cluster and
  the cloud metadata address.
* Deploying a tag instead of a verified digest.
* Runbooks that name commands which do not exist (each one here is backed by a CLI command and
  a test).

## 9. Scalability
The API and workers scale horizontally with HorizontalPodAutoscalers (API 2-10 replicas, workers
2-20, on CPU); PodDisruptionBudgets keep capacity during node maintenance and topology spread
constraints keep replicas apart. The scheduler runs two replicas with one elected leader. Pool
sizes follow the capacity rules of phase 21 (the sum of every process's pool stays below
PostgreSQL's connection limit, or PgBouncer in transaction mode sits in front).

## 10. Next phases
Phase 24 adds the SaaS operations the runbooks call (`argus orgs suspend` and the organisation
lifecycle); phase 25 reviews the deployment with the rest of the threat model.

## 11. Acceptance criteria
* Both overlays render and validate; every workload passes the restricted profile.
* A release migrates and rolls out without a moment of zero ready API pods.
* A compromised account is contained with one command; an audit chain can be exported and
  re-verified offline.
* RPO/RTO targets are written down and checked by quarterly restore drills.
