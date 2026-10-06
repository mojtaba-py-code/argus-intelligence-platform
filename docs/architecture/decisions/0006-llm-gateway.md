# ADR 0006 - Provider-agnostic LLM gateway with data governance

**Context.** The platform must switch models without rewrites, fall back during outages, control
cost, and never send data to a provider that the organisation's policy forbids.

**Decision.** All model calls go through `argus.modules.llm.gateway.LLMGateway`; an import-linter
contract forbids provider SDK imports anywhere else. A request names a *task*
(e.g. `research.plan`) and is rendered from a versioned prompt. The router produces an ordered list
of candidate models for that task and filters it by capability (structured output, tool use,
context size), by **data governance** (the highest classification present in the request versus
the organisation's policy for the provider's locality), by circuit-breaker state and by remaining
budget. Each attempt has a deadline; retryable errors back off with jitter; then the next candidate
is tried. Every call is recorded with tokens, cost, latency, prompt hash and outcome. Outgoing text
passes through secret redaction first.

Providers:

* **Claude** through the official `anthropic` SDK (structured outputs via `output_config.format`,
  adaptive thinking with explicit effort, refusal handling and server-side refusal fallback).
* **OpenAI-compatible** adapter (OpenAI, vLLM, Ollama) - the self-hosted route for data an
  organisation will not send to an external provider.
* **Local extractive** provider - deterministic, no network, implements every task with extractive
  heuristics. Used for tests, offline demos, CI evaluation, and data that must never leave the
  deployment.

**Rejected.** Calling SDKs directly from agents (no central budget, governance or audit); framework
abstractions that hide the prompt, the retries and the cost.
