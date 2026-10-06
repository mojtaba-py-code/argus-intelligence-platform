# Deployment runbook

How a signed release reaches a Kubernetes cluster. Manifests: `deploy/kubernetes`
(Kustomize base + `overlays/staging` and `overlays/production`). Every step that changes
something is reversible or forward-fixable; nothing here needs cluster-admin beyond the initial
namespace.

## 1. Prerequisites (once per environment)

| Dependency | Requirement |
|---|---|
| PostgreSQL | 16 or 17 with `pgvector` >= 0.8, TLS (`verify-full`), point-in-time recovery enabled (see [backup-restore.md](backup-restore.md)) |
| Redis | 7+ with TLS (`rediss://`) and a password; no persistence needed |
| Object storage | S3-compatible bucket, versioning on, server-side encryption, no public access |
| ClamAV | `clamd` reachable on 3310 in namespace `argus-scanning` |
| SMTP | submission (587) with STARTTLS |
| OpenTelemetry | an OTLP/HTTP collector over https (configuration: `deploy/observability/otel-collector.yaml`) |
| Prometheus | scraping with the metrics token; rules from `deploy/observability/prometheus/rules` |
| Secret store | External Secrets / Vault / cloud secret manager - the source of the two Secrets below |
| Ingress | TLS-terminating controller in namespace `ingress-nginx` (or adjust the NetworkPolicy) |

**Database roles** (as the database superuser, once):

```sql
CREATE ROLE argus_owner LOGIN PASSWORD '...';                 -- schema owner: migrations only
CREATE ROLE argus_app LOGIN PASSWORD '...'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;             -- runtime: no DDL, RLS applies
CREATE DATABASE argus OWNER argus_owner;
REVOKE ALL ON DATABASE argus FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE argus TO argus_app;
\c argus
CREATE EXTENSION IF NOT EXISTS vector;
```

**Secrets**: create `argus-runtime` and `argus-owner` from your secret store, following
`deploy/kubernetes/secrets.example.yaml`. Generate key material with `argus keys generate`.
`argus-runtime` never contains the owner DSN: API, workers and the scheduler cannot change the
schema even if compromised. Back up the key material separately from the database (without the
encryption keys a restored database is unreadable; without the audit HMAC key it is
unverifiable).

## 2. Release a version

1. Merge to `main` with green CI. Tag `vX.Y.Z` and push the tag.
2. `release.yml` re-runs the full CI on the tag, builds amd64+arm64 with SBOM and provenance,
   scans the digest, signs it keylessly and verifies the signature. Approve the `release`
   environment when asked.
3. Note the digest from the job summary.

## 3. Deploy (staging first, then production)

```bash
# 1. Verify the signature and the signer identity - never deploy an unverified digest.
cosign verify ghcr.io/mojtaba-py-code/argus-intelligence-platform@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/mojtaba-py-code/argus-intelligence-platform/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# 2. Pin the overlay to that digest (commit this change: the overlay is the record of what runs).
cd deploy/kubernetes/overlays/staging
kustomize edit set image argus=ghcr.io/mojtaba-py-code/argus-intelligence-platform@sha256:<digest>

# 3. Apply. Jobs are immutable, so the previous release's migration Job is removed first.
kubectl -n argus delete job argus-migrate --ignore-not-found
kustomize build . | kubectl apply -f -
kubectl -n argus wait --for=condition=complete job/argus-migrate --timeout=30m
kubectl -n argus rollout status deployment/argus-api deployment/argus-worker deployment/argus-scheduler
```

Why this order is safe: a pod reports ready only when the database is at - or ahead of - the
migration head its image ships (`/health/ready`). New pods therefore receive no traffic until
the migration Job has finished, while old pods keep serving on the newer schema (migrations are
written to stay backward compatible for one release). The rollout never has a moment without
ready pods.

**Smoke test** (staging): `/health/ready` through the ingress; sign in; list projects; run a
small research job; check the security summary; confirm metrics in Grafana and one trace in the
trace store.

## 4. Roll back

* **Application**: set the overlay back to the previous signed digest and apply. Migrations are
  backward compatible for one release by convention (add columns before using them, remove them a
  release later), so the previous image runs on the new schema.
* **Database**: migrations are not downgraded in production. A broken migration is fixed by a new
  migration; data damage is repaired from point-in-time recovery
  ([backup-restore.md](backup-restore.md)).

## 5. Routine operations

| Task | Command |
|---|---|
| Configuration check | `argus config check` (fails on any insecure production setting) |
| Queue state | `argus jobs depth`, `argus jobs dead`, `argus jobs requeue <id>` |
| Stop AI activity platform-wide | `argus killswitch engage --kind all --target '*' --reason "..." --by <you>` (owner role) |
| Verify every audit chain | `argus audit verify` (also the daily `argus-audit-verify` CronJob) |
| Export an audit chain as evidence | `argus audit export --chain <org id or platform> --output evidence.jsonl` |
| Contain a compromised account | `argus users disable --email <address> --reason "..."` |
| Scale workers to zero (emergency) | `kubectl -n argus scale deployment/argus-worker --replicas=0` (and suspend its HPA) |

Commands that need the owner role (`db migrate`, `audit`, `killswitch`) refuse to run in
production without `ARGUS_DATABASE__MIGRATION_URL`; run them from the operator Job pattern
(`deploy/kubernetes/base/operator-jobs.yaml`) or an operator workstation with that secret.
