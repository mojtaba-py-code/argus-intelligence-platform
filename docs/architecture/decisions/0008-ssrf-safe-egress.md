# ADR 0008 - SSRF-safe egress with DNS pinning

**Context.** URLs reach the fetcher from search results and LLM output - attacker-influenced input.
URL-string checks are bypassed by DNS (a public name resolving to `127.0.0.1`), by DNS rebinding
(the name resolves differently at check time and at connect time), by redirects, and by exotic
literals (`http://2130706433`, `http://0x7f.1`, `http://[::ffff:127.0.0.1]`).

**Decision.** `argus.security.egress` implements an httpcore network backend that, for every
connection, parses and normalises the host (IDNA; inet_aton-style IPv4 forms), resolves it, rejects
the request if **any** resolved address is non-public (loopback, RFC 1918, CGNAT, link-local
including cloud metadata, ULA, multicast, reserved, and NAT64 / 6to4 / Teredo / IPv4-mapped forms
that embed a blocked IPv4), and then **connects to the validated IP** while TLS still verifies the
original hostname through SNI. Redirects are followed manually; every hop is re-validated, with a
hop limit and no HTTPS-to-HTTP downgrade. Proxy environment variables are ignored
(`trust_env=False`). Bodies are streamed with byte caps applied *after* decompression with bounded
inflation, under an overall deadline, and the declared content type must match an allow-list and
the magic bytes.

**Consequences.** The guard sits underneath the HTTP client, so every redirect and retry passes
through it. Production adds network-level egress policy (deny RFC 1918 and metadata ranges from
worker pods) as an independent second layer.

**Rejected.** Hostname deny-lists; validating once and letting the HTTP client resolve again.
