# Phase 11 - LLM gateway

## 1. Purpose
One door for every model call, so that cost, data governance, reliability and auditability are
properties of the platform rather than of each feature. Callers name a *task* and hand over a
versioned prompt plus any untrusted material; the gateway decides which model may serve it,
calls it safely, validates the output and accounts for every attempt.

## 2. Architecture
```
caller (RAG answer, later agents)
  └─ PromptService.render(name, variables)       versioned YAML, active version per environment
  └─ LLMGateway.generate(LLMRequest, CallContext)
       route = routing.yaml[task]                exact → longest "prefix.*" → default
       for model in route:
         skip if: not configured · no local handler · no structured output · context too small
                  · data policy (classification × locality) · circuit open · worst-case cost > budget
         attempts: provider.complete()  ── transient → backoff (jitter, Retry-After) → retry
                                           refusal / truncation / fatal → next model
                                           schema-invalid → one repair attempt → next model
         every attempt (and every skip) → ledger: llm_requests + llm_usage_daily (+ job spend)
  providers: Claude (anthropic SDK) · OpenAI-compatible (OpenAI, vLLM, Ollama) · local extractive
```
`POST /orgs/{org}/projects/{project}/ask` is the first consumer: retrieval (phase 10) → the
`knowledge.answer` prompt → **mechanical citation check** → an answer whose every supported claim
quotes text that is really in the cited chunk.

## 3. Why these technologies
* **The official Anthropic SDK** (`anthropic` 1.x, on `httpx2`): typed requests, streaming, the
  server-side refusal fallback and `transform_schema` for structured outputs - with SDK retries
  disabled because the gateway owns retries, fallback and accounting.
* **Claude Opus 5.5** for planning, analysis, verification and reports, **Sonnet 5.5** for bulk
  extraction, **Haiku 4.5** for classification - each route ending in `local/extractive`.
* **YAML routing and prompts**: reviewable in pull requests, validated at start-up, versioned.
* **Jinja2 `SandboxedEnvironment` + `StrictUndefined`** for templates.

## 4. Security and governance
* **Data policy before the network**: a request's classification is the highest of its parts;
  a model whose locality's ceiling is lower is skipped (`blocked_policy` in the ledger), unless
  the organisation allows approvals and the job was approved. Defaults: external models receive
  at most *internal* data, so confidential documents are answered by the local provider unless an
  administrator raises the ceiling - secure by default, explicit to change.
* **Trust boundaries in the prompt**: system prompts are static (the registry rejects variables
  in them); user input enters only declared, type-checked, sanitised template variables;
  retrieved text enters only as nonce-delimited `<<data>>` blocks, with a preamble that it is data,
  and delimiter look-alikes are neutralised.
* **Outbound redaction**: credential-shaped strings are replaced before text leaves the process.
* **Output is untrusted**: Pydantic validation, one repair attempt, then the next model; citation
  quotes are verified against the evidence; fabricated support is flagged, never shown as fact.
* **Refusals**: `stop_reason` is checked before content. **The server-side refusal fallback is
  enabled by default** for Claude Opus 5.5 and Sonnet 5.5 (`fallbacks: "default"`, beta
  `server-side-fallback-2026-07-01`): a safety-classifier false positive is retried by Anthropic on
  its recommended model inside the same call, and the ledger records which model served it.
  Disable with `ARGUS_LLM__ANTHROPIC_REFUSAL_FALLBACK=false`.
* **Budgets**: worst-case cost is checked against the organisation's monthly budget and the job's
  budget before every call; actual cost is charged after it; nothing affordable → 402.
* **Supply chain**: only `argus.modules.llm` may import provider SDKs (import-linter contract
  covering every other package).

## 5. Files
`modules/llm/{types,routing,prompts,deployments,gateway,ledger,models,governance}.py`,
`modules/llm/providers/{base,claude,openai_compatible,local}.py`, `configs/llm_routing.yaml`,
`prompts/knowledge.answer/v1.yaml`, `modules/knowledge/answer.py`, `apps/api/v1/knowledge.py`
(`/ask`), `apps/cli/main.py` (`argus prompts list|deploy`), `migrations/versions/0008_llm_ledger.py`.

## 6. Code worth reading
* `gateway.py::_skip_reason` and `_run_model` - the whole policy of a model call in ~120 lines.
* `providers/claude.py` - what a correct call to a current Claude model looks like: streaming,
  effort instead of a thinking budget, no sampling parameters, structured outputs, refusal first.
* `knowledge/answer.py::verify` - why a citation is only as good as the quote it contains.

## 7. Tests
* `tests/unit/test_llm_units.py` - routing resolution and validation, prices, prompt-registry
  rules (static system prompt, declared variables, schema imports, file naming), rendering and
  sanitising, the template sandbox, nonce-delimited composition, and both SDK adapters against a
  mocked HTTP transport (Claude's streamed events included): request shape, fallback opt-in,
  stop reasons, error classification.
* `tests/integration/test_llm_gateway.py` - pricing and ledger rows, retries, refusal fall-through,
  schema repair, explicit failure, data-policy blocks and the approval escape hatch, outbound
  redaction, monthly and job budgets, circuit breaking, prompt deployment and rollback.
* `tests/integration/test_answers.py` - `/ask` end to end: local answers for confidential evidence,
  the external model for internal evidence, fabricated quotes flagged, no evidence → no call,
  permissions.

## 8. Common mistakes avoided
Calling SDKs from features; SDK-level retries stacked under application retries; reading
`content[0]` before `stop_reason`; disabling thinking or sending `temperature` to models that
reject it; forced `tool_choice` (rejected by current models - structured outputs instead);
interpolating retrieved text into the system prompt; trusting model citations; counting only
successful calls toward cost.

## 9. Scalability
Process-local circuit breakers (no shared single point of failure); the ledger is append-only
with a daily roll-up for cheap budget checks; prompts and routes are cached in memory; streaming
avoids long-request timeouts.

## 10. Next phases
Phases 12-14 build the planner and specialised agents on `LLMGateway` (each agent run gets its
own budget via `CallContext.agent_run_id`), registering local handlers for their tasks; phase 15
reuses the citation verifier for report claims; phase 16 evaluates prompts and models through the
same gateway.

## 11. Acceptance criteria
- [x] No module but the gateway imports a provider SDK (enforced in CI).
- [x] Data above a model's allowed classification never reaches it; skips are recorded.
- [x] Transient failures retry with backoff; refusals and failures fall through to the next model.
- [x] Every attempt is priced and recorded; budgets stop calls before they are made.
- [x] Prompts are versioned, validated at start-up, and can be rolled back without a deploy.
- [x] Answers cite evidence, and every citation is checked against the cited text.
