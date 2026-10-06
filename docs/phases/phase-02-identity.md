# Phase 2 - Authentication, authorisation primitives and the audit log

## 1. Purpose
Know *who* is calling - reliably, revocably, without leaking whether an account exists - and keep
a tamper-evident record of every security-relevant thing that happens.

## 2. Architecture
```
POST /auth/login ─▶ limiter(ip) ─▶ limiter(e-mail) ─▶ Argon2id verify (dummy for unknown)
     │                                               └▶ progressive DB lockout (backstop)
     ├─ MFA off ─▶ session + refresh token (hash) + EdDSA access token
     └─ MFA on  ─▶ single-use challenge (5 min, 5 attempts) ─▶ /auth/mfa/verify ─▶ session
request ─▶ Bearer JWT ─▶ verify (alg/kid/typ/iss/aud/exp) ─▶ session alive? (Redis ▸ PostgreSQL)
```
Every state change writes an audit event *in the same transaction*; failures that roll back are
recorded with `record_detached` in their own transaction.

## 3. Technology choices
Argon2id (memory-hard, PHC winner), PyJWT with **EdDSA** (asymmetric; verification needs no
secret), opaque refresh tokens (revocable), pyotp for RFC 6238 arithmetic only (replay
protection and constant-time checks are ours), GCRA rate limiting in Redis Lua.

## 4. Security considerations
| Threat (threat-model id) | Control | Where |
|---|---|---|
| Brute force, credential stuffing (A1) | GCRA per IP and per *attempted* e-mail; progressive DB lockout | `ratelimit.py`, `AuthService.login` |
| Enumeration (A2) | identical responses, dummy hashing, lockout keyed by any string | `AuthService.register/login/forgot_password` |
| Stolen refresh token (A3) | rotation + reuse detection revokes the whole session, e-mail alert | `AuthService.refresh` |
| Token forgery / alg confusion (A4) | pinned `EdDSA`, `typ=at+jwt`, required claims, keyring by `kid` | `tokens.py` |
| Logout not effective (A5) | per-request session check, write-through revocation cache | `session_cache.py` |
| MFA bypass (A6) | step must be newer than the last used step; challenge attempt cap | `totp.py`, `verify_mfa` |
| Secrets in logs/responses (A7) | tokens prefixed (`argus_rt_`, `argus_ot_`, `argus_mc_`) so redaction recognises them; links carry tokens in the URL fragment | `emails.py`, `redaction.py` |
| Reset-token theft (A9) | 256-bit, hashed, 30 min, single use, all sessions revoked | `reset_password` |
| Audit tampering (X1) | append-only (grants + trigger), per-chain HMAC with key outside the DB, verification CLI | `audit/service.py`, `argus audit verify` |

## 5. Files
`security/{keys,passwords,tokens,totp,ratelimit,permissions,principals}.py`,
`modules/identity/{models,repository,schemas,service,session_cache,emails}.py`,
`modules/audit/{models,service}.py`, `apps/api/security.py`, `apps/api/v1/auth.py`,
`migrations/versions/0002_identity_and_audit.py`.

## 6. Code worth reading
* `AuthService.login` computes an *outcome* inside the transaction and raises only after commit,
  so failed-attempt counters are not rolled back by the exception.
* `AuditService.record` deliberately uses a plain `INSERT` (no `RETURNING`, no key prefetch):
  under RLS PostgreSQL applies the SELECT policy to returned rows, and platform events are not
  readable by the runtime role. The first version failed exactly this way in the tests.
* `MemoryRateLimiter` is LRU-bounded: a fallback limiter that grows without bound is itself a DoS.

## 7. Tests
`tests/security/test_auth_primitives.py` (password policy, JWT attacks incl. `alg: none` and
HS256-with-public-key confusion, TOTP replay, GCRA semantics in memory and in Redis Lua, Redis
outage degradation, role matrix invariants, key loading) and
`tests/integration/test_auth_flows.py` (every flow through HTTP on PostgreSQL, audit tampering
detection by a superuser, runtime role unable to modify audit rows).

## 8. Common mistakes avoided
Returning 404 "user not found" on login; locking accounts permanently; JWT refresh tokens;
storing tokens in plaintext; trusting `alg` from the token header; counting failed logins in a
transaction that the error then rolls back; e-mails that quote user-controlled names.

## 9. Scalability
All checks are O(1) per request; the session check hits Redis and falls back to one primary-key
lookup. Audit appends serialise per chain (per organisation), not globally.

## 10. Next phase
Phase 3 adds organisations, projects, memberships and API keys on top of `Principal`, and starts
using RLS-protected tenant units of work (`Database.tenant(scope)`).

## 11. Acceptance criteria
- [x] Replayed refresh token revokes the session (all tokens of it stop working).
- [x] Unknown e-mail and wrong password produce byte-identical problem documents.
- [x] Known and unknown e-mails lock out identically (5 attempts, then 429).
- [x] TOTP codes cannot be replayed; recovery codes are single use; challenges die after 5 tries.
- [x] Audit chains verify; a superuser edit is detected as `hash mismatch`.
