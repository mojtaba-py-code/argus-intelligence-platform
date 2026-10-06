# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-06

First public release: phases 1-25 of the [roadmap](docs/roadmap.md), except phase 18 (knowledge
graph), which was left out by decision.

### Added

- Research jobs: plan → collect → analyse → verify → detect contradictions → report, with
  budgets, human approvals, progress streaming and Markdown, JSON, CSV and PDF reports.
- Knowledge base for PDF, DOCX, HTML, Markdown, CSV, JSON and text: malware scanning, parsing in
  a sandboxed subprocess, chunking, embeddings and hybrid keyword + vector search with
  authorisation inside the SQL.
- Secure web research: SSRF guard with DNS pinning and per-hop redirect checks, size, time and
  decompression limits, robots.txt, per-domain politeness and source reputation.
- LLM gateway for Claude, OpenAI-compatible and offline local models, with a data-classification
  policy, per-agent tool permissions and budgets, and kill switches.
- Evidence verification: verified quotes for every finding, figure checks, contradiction
  detection, confidence scores and end-to-end prompt-injection defences.
- Continuous monitoring of pages and searches with change significance scoring and in-app and
  e-mail notifications.
- SaaS operation: organisations, roles, restricted projects, API keys, service accounts, plans,
  quotas, retention, suspension, deletion with a grace period, restore, purge and owner export.
- Security center: daily audit-chain verification, security events, recommendations and
  kill-switch administration.
- Observability: OpenTelemetry traces, Prometheus metrics, alert rules with runbooks and a
  Grafana dashboard; web dashboard at `/app`.
- Delivery: Docker Compose stack, Kubernetes manifests (kustomize, network policies), CI with
  static analysis, tests on Python 3.12-3.14 against PostgreSQL, CodeQL, Semgrep, Bandit,
  gitleaks, pip-audit and Trivy, and signed multi-architecture release images with SBOM and
  provenance.
- Security policy, contributing guide, code of conduct and issue and pull request templates.

### Fixed

- The parser sandbox always answers with exactly one reply: running out of memory while parsing,
  or while encoding a large result, is reported as `memory_limit` instead of a crash.
- Release images build for arm64 as well as amd64 (QEMU emulation on the runner).
- The secret scan works on pull requests (it reads the automatic, read-only job token).

### Security

- Base image updated to a rebuild with the fixed `libpcre2-8-0` (CVE-2026-103111).

[Unreleased]: https://github.com/mojtaba-py-code/argus-intelligence-platform/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mojtaba-py-code/argus-intelligence-platform/releases/tag/v0.1.0
