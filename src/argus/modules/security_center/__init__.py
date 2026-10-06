"""Security operations for organisation administrators (phase 19).

* **Audit integrity**: every organisation's audit chain is re-verified on a schedule; a broken
  chain is recorded, audited and reported to the organisation's administrators.
* **Kill switches**: administrators stop an agent, tool, provider or model for their own
  organisation; platform-wide switches stay operator-only and are shown read-only.
* **Posture**: a security summary (denied access, agent tool denials, prompt-injection
  detections, blocked egress, model policy blocks, credentials hygiene) with deterministic
  recommendations, and a feed of security-relevant audit events.
* **Denied access**: permission denials of organisation members are written to the audit log
  under a per-principal budget, so probing is visible without letting it flood the log.
"""
