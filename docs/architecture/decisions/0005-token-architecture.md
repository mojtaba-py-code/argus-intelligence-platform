# ADR 0005 - EdDSA access tokens, opaque rotating refresh tokens

**Context.** We need stateless request authentication, immediate revocation on logout or
compromise, and resistance to stolen refresh tokens.

**Decision.**

* **Access token**: JWT signed with `EdDSA` (Ed25519), lifetime 10 minutes, claims `iss`, `aud`,
  `sub`, `sid` (session id), `iat`, `nbf`, `exp`, `jti`, `amr`. Verification pins the algorithm,
  issuer and audience and requires every time claim. A `kid` header selects the key; several
  verification keys may be active during rotation; public keys are published as a JWKS document.
* **Session check**: every request confirms that `sid` is not revoked (PostgreSQL, with a short
  Redis cache), so logout and "revoke all sessions" take effect immediately, not at token expiry.
* **Refresh token**: 256-bit random, opaque, stored as SHA-256, single use. Each use issues a child
  token; presenting an already-used token is treated as theft and **revokes the whole session**
  (refresh-token rotation with reuse detection, OAuth 2.0 Security BCP).
* **API keys**: `argus_sk_<id>_<secret>`. The id is public and indexed; the secret is verified with
  HMAC-SHA-256 under a server-side pepper in constant time. Keys carry scopes that are intersected
  with the owning principal's role at every request.
* Credentials are accepted only in the `Authorization` header. A token-looking query parameter is
  rejected outright so a credential can never land in access logs or `Referer` headers.

**Rejected.** HS256 (every verifier holds the forging key); long-lived access tokens (no
revocation); JWT refresh tokens (revocation needs a lookup anyway, so the JWT adds only risk).
