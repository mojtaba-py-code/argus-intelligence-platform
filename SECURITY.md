# Security policy

Security is the design constraint of Argus, so reports are welcome and taken seriously.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (`main`) | ✓ |
| older | ✗ |

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a vulnerability.**

Report it privately through GitHub:
[**Security → Report a vulnerability**](https://github.com/mojtaba-py-code/argus-intelligence-platform/security/advisories/new).
Only the maintainer can read the report, and the fix can be prepared in a private fork before
anything is disclosed.

A useful report contains:

* the affected component (for example `src/argus/security/ssrf.py`) and version or commit;
* the impact - what an attacker gains, and which privileges or configuration they need;
* step-by-step reproduction, ideally a failing test in the style of `tests/security/`;
* any suggested fix.

Reports are triaged on a best-effort basis. You will be told whether the report is accepted,
kept informed while a fix is prepared, and credited in the advisory unless you prefer otherwise.
Please give a reasonable time to release a fix before any public disclosure.

## Scope

In scope - anything that breaks a guarantee described in the
[security model](docs/security/security-model.md) or the
[threat model](docs/security/threat-model.md), for example:

* crossing tenant boundaries (row-level security, authorisation inside retrieval queries);
* authentication, session, token, API-key or MFA weaknesses;
* SSRF or egress-policy bypasses in the web fetcher;
* prompt injection that makes an agent use a tool or reach data it was not granted;
* sandbox escapes in document parsing, or malicious-file handling;
* tampering with the audit chain that verification does not detect;
* secrets or personal data leaking into logs, traces, metrics or exports.

Out of scope:

* findings that need `ARGUS_ENVIRONMENT=development` or `testing`, or settings that
  `argus config check` rejects for staging and production;
* the deterministic test-only key material in `tests/`, and the documented development
  passwords in `.env.example` and `scripts/local_postgres.py`;
* denial of service by volume alone, and missing hardening with no demonstrated impact.

## Supply chain

* Every GitHub Action is pinned to a full commit SHA, and every workflow starts from a
  read-only token.
* CI runs CodeQL, Semgrep, Bandit, gitleaks (full history), `pip-audit` against the hash-pinned
  lock file, and Trivy on the container image; Dependabot keeps dependencies current.
* Release images are signed keylessly with Sigstore cosign and carry an SBOM and SLSA provenance;
  verify a digest before deploying as described in
  [deployment](docs/operations/deployment.md).
