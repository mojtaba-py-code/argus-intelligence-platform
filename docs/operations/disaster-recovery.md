# Disaster recovery

Scenarios beyond a single bad deploy, with the recovery path and the objective for each. Backup
mechanics, verification and drills: [backup-restore.md](backup-restore.md).

## 1. Objectives

| Scenario | RPO | RTO | Path |
|---|---|---|---|
| Lost pod, node or zone | 0 | minutes | replicas spread across zones, PodDisruptionBudgets, leases re-queue jobs |
| Database primary failure | < 1 minute (synchronous standby) or 5 minutes (PITR) | 15 minutes managed failover; 1 hour PITR | provider failover; otherwise point-in-time restore |
| Logical damage (bad migration, mass deletion) | 5 minutes before the damage | 1 hour | point-in-time restore to a new instance, verify, switch |
| Region loss | 15 minutes | 4 hours | restore from cross-region backups and the replicated bucket in the standby region |
| Ransomware / attacker with infrastructure access | last verified backup before compromise | 1 day | clean environment, credentials rotated, restore, audit chains verified |
| Loss of key material | - (prevent) | - | secret manager replication; without encryption keys data is unrecoverable by design |

## 2. Principles
* **Backups are only as good as their last restore**: quarterly drills measure the real RPO/RTO.
* **Key material is backed up separately from data**, with different access: one stolen backup
  should never contain both ciphertext and keys.
* **Rebuild, don't repair, after a compromise**: new cluster, new credentials, images verified
  by signature, data from a backup whose audit chains verify.
* **Everything that is not data is code**: manifests, overlays (pinned digests), alert rules,
  dashboards and the collector configuration live in Git and are re-applied, not restored.

## 3. Region-loss runbook
1. Incident commander declares DR; freeze changes in the primary region (if reachable).
2. In the standby region: create the Kubernetes namespace from Git
   (`deploy/kubernetes/overlays/production` with the standby's endpoints), restore PostgreSQL
   from the cross-region backup to the latest point, point storage at the replicated bucket,
   restore the two Secrets from the replicated secret manager.
3. Verify ([backup-restore.md §4](backup-restore.md#4-verifying-a-restore-every-restore-and-every-drill)),
   including `argus audit verify`.
4. Switch DNS to the standby ingress; watch the alerts and the error ratio.
5. Communicate the lost window to tenants; jobs that were running resume from checkpoints, and
   monitors catch up on their next scheduled run.

## 4. After a compromise
1. Contain and preserve evidence ([incident-response.md](incident-response.md)).
2. Build a clean environment: new cluster credentials, new database passwords, new Redis
   password, new provider keys, new JWT signing key (all sessions end), new encryption key for
   new data.
3. Choose the restore point: the latest backup *before* the first malicious action in the audit
   log, whose chains verify.
4. Restore, verify, deploy only signed digests, then reopen to tenants.
