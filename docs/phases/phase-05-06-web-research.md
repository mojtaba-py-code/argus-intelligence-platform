# Phases 5-6 - Secure web research

Phase 5 (web collection) and phase 6 (untrusted-content handling) ship together because neither
is safe without the other: a fetcher that extracts text without treating it as hostile is a
prompt-injection pipe, and an injection classifier without a safe fetcher is decoration.

## 1. Purpose
Let the platform read the public web on a tenant's behalf **without** becoming a proxy into its
own network (SSRF), a scraper that ignores site owners (robots.txt, politeness), or a channel for
instructions hidden in web pages (prompt injection). Every page read is recorded with provenance
so later phases can cite it, re-verify it and detect when it changes.

## 2. Architecture
```
POST /sources ─▶ validate URL (static SSRF rules) ─▶ rate limit (per org)
              └─(one transaction)─▶ sources row + jobs row (dedup) + audit "source.added"
worker: sources.fetch ─▶ SourceService.collect(url)
collect:  upsert source ─▶ domain policies ─▶ SafeFetcher.fetch(url, gate=…)
          gate (per hop, redirects included): domain policy → robots.txt (cached) → politeness
          SafeFetcher: GuardedNetworkBackend (resolve once, refuse any private answer, connect
                       to the validated IP) → bounded body/decompression → content sniffing
          extract (HTML: hidden text separated) → Unicode sanitising → injection assessment
          → reputation prior (+ org override) → snapshot (deduplicated by content hash)
search providers (Brave / SearXNG / static) only produce *candidate* URLs for collect
```

## 3. Why these technologies
* **httpcore with a custom network backend** (ADR 0008): the only point where the resolved
  address can be checked *and* pinned. Validating a URL and then letting a client resolve it
  again is the classic DNS-rebinding hole.
* **selectolax (lexbor)**: a fast C HTML parser - but quadratic on pathological nesting, so a
  linear pre-scan (`check_structure`) refuses hostile structure before parsing.
* **Protego** for robots.txt: implements RFC 9309 wildcards (`*`, `$`) that the standard
  library's `urllib.robotparser` ignores.
* **Redis (GCRA)** for politeness, so all workers share one per-host budget.

## 4. Security considerations
* **SSRF, layered.** Static URL rules (schemes, credentials in URLs, ports, `inet_aton` IPv4
  forms such as `0x7f.1`, IPv6 transition forms such as `::ffff:127.0.0.1`, NAT64, 6to4,
  Teredo, internal suffixes like `.local`/`.internal`) **plus** the connect-time check on every
  resolved address. Redirects are followed manually and each hop is re-validated; HTTPS→HTTP
  downgrades are refused. Tests prove blocked addresses are **never contacted**.
* **Resource limits.** Total deadline, body limit, streaming decompression with a ratio limit
  (gzip bombs), declared vs. sniffed content type (an "HTML" response that is really an
  executable is refused), structure limits for HTML, recursion-safe JSON handling.
* **Prompt injection is data, not instructions.** Hidden elements (`display:none`, zero font
  size, `[hidden]`, `aria-hidden`) are removed from the text and kept aside; invisible Unicode
  (tags, bidi overrides) is stripped and counted; a multilingual heuristic scores override,
  role-spoofing, exfiltration, secret-probing, tool-coercion and obfuscated phrasing. Instructions
  in hidden text score "high". The score is stored with the snapshot and travels with the text
  into later phases, where the agent architecture (ADR 0007) - not the classifier - is the real
  defence: untrusted text never reaches a model with tools it could misuse.
* **Domain policies.** Organisations can block a domain, require human approval, or override the
  reputation prior; the most specific policy wins and blocked domains are refused **before**
  robots.txt is even requested.
* **robots.txt (RFC 9309).** 4xx = no restrictions; 5xx/unreachable = assume complete disallow
  (cached for 5 minutes); an SSRF-blocked host reports "blocked", never a cached disallow.
* **Abuse limits.** Source additions are rate-limited per organisation, because every addition
  causes outbound traffic; per-host politeness alone would not stop fan-out across many hosts.
* **Tenant isolation.** `sources`, `source_snapshots` and `domain_policies` have RLS and
  composite same-tenant foreign keys (a forged row pointing at another tenant's source is
  refused by the database - tested).
* **Search results are untrusted.** Every result URL is re-validated, titles and snippets are
  sanitised, and a result is only a candidate for `collect`, which applies everything above.

## 5. Files
`security/{ssrf,egress,fetcher,content,text,html,injection}.py`,
`modules/sources/{models,schemas,service,robots,search,reputation,tasks}.py`,
`configs/source_reputation.yaml`, `apps/api/v1/sources.py`,
`migrations/versions/0005_sources.py`.

## 6. Code worth reading
* `security/egress.py::GuardedNetworkBackend.connect_tcp` - the single choke point for every
  outbound connection, including redirects and keep-alive reconnects.
* `security/fetcher.py::SafeFetcher._fetch` - the redirect loop and the order of checks.
* `modules/sources/service.py::SourceService._gate` and `collect` - how policy, robots.txt and
  politeness become per-hop checks, and how failures become source states.
* `security/injection.py::assess` - why scores combine as `1 - Π(1 - w)` (independent evidence)
  and why the compact-phrase check defeats `i.g.n.o.r.e` obfuscation.

## 7. Tests
* `tests/security/test_ssrf.py`, `test_fetcher.py` - URL parsing edge cases, every private and
  reserved range, rebinding, redirects into private space, decompression bombs, timeouts,
  content mismatch (in-memory network, no sockets).
* `tests/security/test_untrusted_text.py` - Unicode sanitising, hidden-text extraction, the
  nesting pre-scan, multilingual and obfuscated injection detection, false-positive checks.
* `tests/unit/test_web_research.py` - robots.txt rules and status codes, Redis-shared robots
  cache, politeness spacing, search providers (request shape, result validation), fail-fast
  search settings, reputation priors and label-boundary matching.
* `tests/integration/test_sources.py` - API → queue → worker → fetch → snapshot with provenance;
  dedup; robots; SSRF through redirects and DNS; hidden injection flagged; domain policies;
  scopes; tenant isolation (API, RLS and foreign keys); pagination; rate limiting.

The fake internet (`tests/fake_network.py`) sits *below* the real SSRF guard, so the tests
exercise production code paths and can assert which addresses were contacted.

## 8. Common mistakes avoided
Validating the URL but letting the HTTP client resolve the name again; following redirects
automatically; trusting `Content-Type`; `urllib.robotparser` (no wildcards); treating a robots.txt
5xx as "allowed"; stripping hidden text and throwing it away (it is evidence of an attack); using
`requests`/`httpx` with `trust_env=True` (environment proxies would bypass every check).

## 9. Scalability
Fetches run in workers (horizontal); robots.txt and politeness state live in Redis so all
workers share them; snapshots are deduplicated by content hash, so periodic re-checks of an
unchanged page cost one `UPDATE`.

## 10. Next phases
Phase 7 plugs PDFs into `SourceService.binary_extractor` (the document pipeline). Phases 8-10
chunk and index snapshots for retrieval. Phase 12-14 stages call `search` + `collect` and route
`needs_approval` outcomes into the approval workflow from phase 4. Phase 17 re-collects sources
on a schedule and uses snapshot hashes for change detection.

## 11. Acceptance criteria
- [x] Private, loopback, link-local, metadata and transition-form addresses are refused - by URL,
      by DNS answer and by redirect - and are never contacted.
- [x] robots.txt is honoured (wildcards, agent groups, crawl-delay capped, RFC 9309 status codes)
      and cached across workers.
- [x] Each host sees at most one request per interval across all workers.
- [x] Hidden prompt injection is removed from the text, preserved as evidence and flagged "high".
- [x] Every snapshot records URL, final URL, redirects, status, media type, server IP, time and
      content hash; unchanged content is not stored twice.
- [x] Domain policies (block / approval / allow + reputation override) work and are audited.
- [x] Another tenant cannot see or reference sources, through the API or directly in SQL.
