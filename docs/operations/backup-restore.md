# Backup and restore

## 1. Targets

| Asset | RPO (data loss) | RTO (time to restore) | How |
|---|---|---|---|
| PostgreSQL (all tenant data, audit log, queue) | 5 minutes | 1 hour in-region | continuous WAL archiving + daily base backups (point-in-time recovery) |
| Object storage (document blobs) | 0 for deletions/overwrites within 30 days; 15 minutes for region loss | 1 hour | bucket versioning + cross-region replication |
| Key material (encryption, audit HMAC, JWT, pepper, signing) | 0 | 15 minutes | secret manager with versioning and its own replication - never only in a database backup |
| Configuration (manifests, overlays, alert rules) | 0 | minutes | Git (the overlay pins the deployed digest) |
| Redis | none needed | minutes | caches, rate-limit counters and revocation hints only - rebuilt on demand |

The targets are realistic for a managed PostgreSQL service with PITR and a versioned bucket; they
are commitments only once a restore drill (section 5) has met them.

## 2. What is backed up, and how it is protected

* **PostgreSQL**: the provider's PITR (or pgBackRest/WAL-G for self-managed clusters):
  `archive_mode = on`, WAL shipped at least every 60 s (`archive_timeout = 60`), a base backup
  daily, retention 35 days, a copy in a second region. Backups are encrypted at rest with a
  KMS key that the application roles cannot use; restore rights belong to operators only.
* **Defence in depth inside the data**: document blobs are envelope-encrypted by the application
  (AES-256-GCM with a per-object key wrapped by the keyring), and secrets in the database (TOTP
  seeds) are encrypted too - a stolen storage or database backup without the key material
  yields ciphertext.
* **Object storage**: versioning on (overwrites and deletions are recoverable for 30 days via a
  lifecycle rule on non-current versions), replication to a bucket in another region, object
  lock (compliance mode) for audit exports.
* **Key material**: in the secret manager, versioned. Rotation keeps old versions: old encryption
  keys stay in `ARGUS_SECURITY__ENCRYPTION_KEYS` (decrypt only) while new data uses the active
  key; the audit HMAC key must outlive every chain it signed.
* **Audit evidence**: `argus audit export --chain <id> --output <file>` writes a self-contained,
  re-verifiable copy; store exports in the object-locked bucket after incidents and at least
  monthly for the platform chain.

## 3. Restore procedures

### 3.1 Point-in-time restore (bad migration, accidental mass deletion, corruption)
1. Declare the incident; stop writes: scale `argus-worker` and `argus-scheduler` to 0 and put the
   API in maintenance (scale to 0 or route the ingress to a maintenance page).
2. Restore the cluster to a new instance at the chosen time `T` (just before the damage).
3. Verify the restored database *before* switching (section 4).
4. Point `argus-runtime` (`ARGUS_DATABASE__URL`) and `argus-owner` at the new instance; roll
   out; scale workers and the scheduler back.
5. Jobs that were running at `T` are leased in the restored queue: the reaper re-queues them and
   they resume from their checkpoints.
6. Record the lost window (`T` .. incident time) in the incident report; tenants are told which
   of their actions in that window must be repeated.

### 3.2 Object storage
* Single objects: restore the previous version (`aws s3api list-object-versions` /
  `get-object --version-id` or the provider's equivalent).
* Region loss: switch `ARGUS_STORAGE__S3_ENDPOINT_URL`/bucket to the replica.
* A document row whose blob is missing fails safely: downloads return an error, the integrity
  hash check refuses partial objects.

### 3.3 Key material
Restore the secret versions that were active at the backup's time. A database restored without
its encryption keys cannot decrypt documents or TOTP seeds; without the audit HMAC key its chains
cannot be verified - which is why key material is backed up separately, with its own access
control.

## 4. Verifying a restore (every restore, and every drill)

```bash
argus config check                      # configuration valid for the environment
argus db current                        # expected migration head
argus db check                          # no drift between code and schema
argus audit verify                      # every chain intact - a strong whole-database check
argus jobs depth                        # queue readable
```

Then a smoke test: sign in, open a recent report, download a document (decryption works), run a
small research job end to end. Compare row counts of the largest tables with the source at `T`.

## 5. Restore drills

Quarterly, into an isolated environment (separate network, separate credentials, no outbound
e-mail):
1. Restore production to "now minus 1 hour" from the backups only.
2. Run section 4. Time each step.
3. Record achieved RPO and RTO against section 1; fix whatever missed its target.
4. Destroy the drill environment.
