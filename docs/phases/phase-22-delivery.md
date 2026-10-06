# Phase 22 - Docker and CI/CD hardening

## 1. Purpose
Make what ships equal to what was tested, and make the path from a commit to a running image
resistant to tampering: pinned inputs, least-privilege automation, every gate in CI, signed
outputs with a verifiable identity - and tests that keep those decisions from eroding.

## 2. Architecture
```
pull request ── CI (ci.yml), read-only token, no secrets
   static (ruff, mypy --strict, import contracts, bandit, lock check)
   tests x3 Python (unit, integration, security, query plans, AI evaluation) on PostgreSQL+pgvector
   pip-audit (hash-pinned export) · gitleaks (full history) · Semgrep · CodeQL (codeql.yml)
   deployment config: docker compose config, promtool check config, otelcol validate
   container: build, non-root check, Trivy (fixable HIGH/CRITICAL fail)
   weekly: benchmarks with budgets (pytest -m perf) · new advisories re-checked

tag vX.Y.Z ── release.yml
   verify: the whole ci.yml again on the tagged commit (workflow_call)
   image (environment "release", reviewer-gated):
     buildx amd64+arm64 ─ SBOM (SPDX) + SLSA provenance (mode=max) attestations ─ push by digest
     Trivy on the pushed digest ─ cosign keyless sign ─ cosign verify against the workflow identity
```

## 3. Decisions
* **Everything pinned by content.** Base images and service images by `@sha256` digest, GitHub
  Actions by commit SHA, Python dependencies by `uv.lock` hashes. Tags are mutable; digests are
  not. Dependabot proposes updates weekly with a 7-day cooldown (a compromised release is usually
  yanked within days) - security updates are not delayed.
* **Least privilege in automation.** Every workflow starts with `contents: read`; jobs add only
  what they need (`security-events: write` for CodeQL, `packages: write` and `id-token: write`
  for the release). No `pull_request_target`; checkouts never persist the token; no caches that
  a pull request could poison.
* **Keyless signing.** The release signs the image digest with Sigstore using the workflow's
  OIDC identity - no long-lived signing key exists to steal. Deployments verify the signature
  *and* that the signer was `release.yml` on a version tag of this repository.
* **Attestations travel with the image.** BuildKit attaches an SPDX SBOM and SLSA provenance
  (how, where and from which commit the image was built) to the pushed digest.
* **Configuration is validated by the tools that run it.** Compose files are resolved by Docker
  Compose, alert rules and scrape configuration by `promtool`, the collector configuration by
  `otelcol validate` - using exactly the image versions the stack runs (a test enforces that).
* **The image.** Multi-stage (no compiler or uv at runtime), non-root UID 10001, virtual
  environment owned by root (the process cannot modify its own code), read-only root filesystem
  in compose and Kubernetes, allow-list build context, OCI labels with version and revision,
  `PYTHONFAULTHANDLER` for crash diagnostics.
* **Policy as tests.** `tests/unit/test_delivery_policy.py` fails when an image or action is
  unpinned, a workflow's default token is not read-only, a checkout persists credentials, the
  release stops running full CI or verifying its signature identity, a compose port is published
  beyond localhost or an application container regains privileges.

## 4. Security
| Threat (X5 supply chain, X6 secrets) | Control |
|---|---|
| Malicious or hijacked dependency release | hash-pinned lock; cooldown; pip-audit; Trivy |
| Mutable tag points to different code | digest and SHA pins everywhere, enforced by tests |
| Stolen CI token | read-only default token; no secrets in pull-request jobs |
| Poisoned build cache | no shared caches in CI |
| Image swapped in the registry | deploy by digest; cosign verification of the workflow identity |
| Secret committed | gitleaks pre-commit and full-history CI scan; allow-list build context |

## 5. Files
`Dockerfile`, `.dockerignore`, `.github/workflows/{ci,release,codeql,eval-live}.yml`,
`.github/dependabot.yml`, `.github/actions/setup-python-env`, `tests/unit/test_delivery_policy.py`.

## 6. Common mistakes avoided
* `uses: some/action@v4` (a tag the action's owner - or an attacker - can move).
* Signing with a key stored as a repository secret.
* A release workflow that builds from the tag without re-running the tests.
* `docker compose up` succeeding while Prometheus rejects the alert rules at runtime.
* Publishing data-service ports on all interfaces in development.

## 7. Tests
`tests/unit/test_delivery_policy.py`: base images pinned by digest and the image runs
unprivileged; the build context is an allow-list; every workflow and composite action is pinned
by commit SHA and starts with a read-only token; releases run the full CI and verify the
signature identity; compose images are pinned, ports published on localhost only, application
containers locked down; CI validates configuration with the same image versions the stack runs.
CI itself is the integration test of this phase: every gate above runs on every pull request.

## 8. Scalability
The test matrix runs in parallel jobs, each with its own PostgreSQL service; the image is built
once per release for amd64 and arm64 and promoted by digest (staging and production run the
same bytes); benchmarks run weekly, not on every pull request, so CI time stays predictable as
the suite grows.

## 9. Next phases
Phase 23 deploys only images whose signature verifies, by digest, and validates the Kubernetes
manifests in this same CI; phase 25 reviews the pipeline with the rest of the threat model.

## 10. Acceptance criteria
* CI covers static analysis, three Python versions, dependency audit, secret scan, SAST, CodeQL,
  deployment configuration, the image and its vulnerabilities; weekly benchmarks.
* A version tag produces a multi-arch image with SBOM and provenance, scanned and signed, whose
  signature verifies against the release workflow identity.
* The delivery policy tests pass.
