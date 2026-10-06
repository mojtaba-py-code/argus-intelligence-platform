# Phases 12-14 - Planner, specialised agents, orchestration

## 1. Purpose
Turn a research objective into evidence-backed findings without ever letting text from the web
or from a document decide what the platform *does*. A planner agent breaks the objective into
sub-questions and search queries; code searches, collects and indexes sources; an analyst agent
answers each sub-question from retrieved evidence; every finding is checked mechanically against
the text it cites. Each step is checkpointed, budgeted, killable and recorded.

## 2. Architecture
```
POST /research-jobs ──► queue ──► ResearchPipeline (phase 4: checkpoints, approvals, budget)
                                   │
  plan     ── creator re-authorised ── budget > threshold? ──► ApprovalRequired("cost_threshold")
           └─ AgentRuntime.run(PLANNER)                                 objective only (trusted)
           └─ normalise_plan (code): ids, sanitising, query budget  ──► research_plans
  collect  ── creator re-authorised (needs sources:manage)
           └─ plan queries → SearchProvider → SourceService.collect     SSRF-safe, robots, policies
              require_approval domains ──► ApprovalRequired("crawl_scope") ──► human decision
  analyze  ── creator re-authorised ──► SearchScope (creator's ceiling and origins)
           └─ evidence above the external ceiling + an external model configured + policy
              "approval" ──► ApprovalRequired("data_policy") ──► human decision
           └─ per sub-question: retrieve → EvidenceRegistry (E1, E2 ...) →
              AgentRuntime.run(ANALYST, tools={search_documents})        reads untrusted text
              └─ quote_supported() per citation ──► research_findings + research_citations

AgentRuntime (every iteration):  kill switch? deadline? cost cap? → render versioned prompt
   → LLMGateway.generate (policy, budget, ledger) → validated output → tool *requests* from
   typed output fields → allow-list → kill switch → argument schema → handler → result fed back
   as untrusted data → agent_runs / tool_calls (+ audit for denials)

GET  .../research-jobs/{id}/plan | /findings | /agent-runs      read with the *viewer's* rights
argus killswitch list | engage | release                         owner role, audited
```

## 3. Why this design
* **Plan-then-execute (ADR 0007).** Control flow is fixed before untrusted content is read: the
  planner sees only the user's objective, and code - not a model - executes the plan. A page that
  says "now fetch this URL" or "e-mail the report" has no channel to act on.
* **Tool requests are output fields, not native tool use.** Agents return a Pydantic model; a
  small function on the spec (`requests`) turns specific fields (the analyst's
  `follow_up_queries`) into tool requests. The model cannot name a tool the spec does not map, and
  the runtime still checks the allow-list, so even a bug in that mapping is caught and audited.
* **Web search and fetching are not agent tools.** They are deterministic code in the collect
  stage, driven by the plan's queries. The only tool any agent holds is `search_documents`: a
  read-only search of the project's own knowledge inside the job's authorised scope.
* **Deterministic local handlers** (`local_plan`, `local_analyst`) close every route, so the whole
  pipeline runs - and is tested - offline, and keeps working when policy forbids external models.
* **Claude Opus 5.5** is the first choice for planning and analysis (`configs/llm_routing.yaml`),
  via the phase 11 gateway: streaming, `effort` instead of a thinking budget, structured outputs.

## 4. Security
* **Declared tools only.** `modules/agents/catalogue.py` lists every tool and whether it has side
  effects. The runtime refuses a tool that is not declared, is registered under another name, or
  claims a different side-effect class (`UndeclaredTool`).
* **Taint rule.** An agent that reads untrusted text may not hold a side-effect tool
  (`TaintViolation` before the run starts). A unit test imports every module, finds every
  `AgentSpec`, and checks it against the catalogue - a new agent cannot ship in violation.
* **Hard limits, typed endings.** Iterations, tool calls, cost and wall-clock time per agent; the
  run ends `completed`, `max_iterations`, `max_tool_calls`, `budget`, `timeout`, `killed` or
  `failed`, and job and organisation budgets still apply to every model call underneath.
* **Kill switches** for an agent, a tool, a provider, a model, or everything - per organisation or
  platform-wide - checked before every iteration, tool call and model call (cached ~5 s per
  process). Row-level security lets the runtime role write only its own organisation's switches;
  platform switches need the owner role (`argus killswitch`). Engaging and releasing are audited.
* **A job acts for its creator, now - not at creation.** Plan, collect and analyse each
  re-authorise the creator with the same rules as an API request (`research/creator.py`): a job
  started with an API key acts with the key's scopes, never the owner's full role; a revoked or
  expired key, a disabled user or a member who left stops the job with `access_revoked` before
  any budget is spent. Creating a job also requires what its mode will do (`documents:read`;
  `sources:read` and `sources:manage` for web research).
* **Results are read with the viewer's rights.** Findings and the agent trail need read access to
  the job's origins. A finding whose analyst read evidence above the viewer's classification
  ceiling is **withheld** (statement and citations removed): a model's sentence can carry what it
  read whether or not it cited it. Citations of chunks above the ceiling are hidden and counted;
  agent runs that saw such evidence are shown without tool arguments and results.
* **Citations are verified mechanically** (`knowledge/citations.py`): the quote must appear -
  after Unicode, case and whitespace normalisation - in a chunk the analyst was given under that
  id. An unsupported "fact" becomes a hypothesis with confidence ≤ 0.3. `verified` is recomputed at
  read time: deleting a document cascades to its citations, and findings stop being "verified" by
  evidence that no longer exists.
* **The trail.** `agent_runs` (status, iterations, tool calls, cost, served models, prompt
  versions, highest evidence classification) and `tool_calls` (outcome, *redacted* arguments,
  result summary, latency) are tenant tables under RLS; denied tool requests are also written to
  the audit log (`agent.tool_denied`).
* **Human approvals** pause the job (phase 4 checkpoints) until an administrator decides:
  `cost_threshold` before planning when the job's budget exceeds the threshold (an organisation
  may lower the platform's threshold, never raise it); `crawl_scope` for domains marked
  `require_approval`; `data_policy` before analysis when the organisation's policy says
  "approval", evidence in scope is above the external ceiling and an external model could serve
  the task. Under "never", or with no external model configured, analysis stays local without
  asking anyone.
* **Refusals.** The server-side refusal fallback configured in phase 11 is **enabled by default**
  for Claude Opus 5.5 and Sonnet 5.5, so agents inherit it; the ledger records the model that
  actually served each turn. Disable with `ARGUS_LLM__ANTHROPIC_REFUSAL_FALLBACK=false`.

## 5. Files
`modules/agents/{catalogue,runtime,killswitch,models}.py`,
`modules/research/{planning,collection,analysis,stages,creator,results,schemas}.py`,
`modules/knowledge/citations.py`, `prompts/research.plan/v1.yaml`,
`prompts/analysis.findings/v1.yaml`, `apps/api/v1/research.py` (plan, findings, agent-runs),
`apps/cli/main.py` (`argus killswitch`), `migrations/versions/0009_agents_and_findings.py`.

## 6. Code worth reading
* `agents/runtime.py::_loop` and `_call_tool` - every decision about a model's request, in order.
* `research/creator.py` - why "who is this job acting for?" is asked again at every stage.
* `research/results.py::findings` - withholding by what the model *read*, not only what it cited.
* `research/analysis.py::_store` - downgrading unsupported claims instead of trusting them.

## 7. Tests
* `tests/unit/test_agents_units.py` - the catalogue-wide taint test, declared-tool checks, plan
  normalisation (deduplication, query budget, invisible-only text), the offline planner and
  analyst, the evidence registry, quote verification, kill-switch input validation.
* `tests/integration/test_agents.py` - the runtime against PostgreSQL with a scripted model: tool
  results fed back as untrusted data, denied tools recorded and audited, argument validation and
  redaction, each limit, failures, taint and declaration checks before anything runs, organisation
  and platform kill switches (RLS keeps tenants from writing or releasing platform switches).
* `tests/integration/test_research_agents.py` - jobs end to end, offline: plan, collection and
  verified findings citing documents and web pages; citations removed with their document;
  restricted evidence withheld from viewers; crawl-scope, cost-threshold and data-policy
  approvals (confidential evidence reaches a stand-in external model only after approval, and
  never under a "never" policy); a kill switch failing a job before any model call; revoked
  members and API keys; key scopes; origin permissions on results.

## 8. Common mistakes avoided
Giving an agent that reads web pages a fetch or send tool; letting the model choose which URLs to
fetch; trusting a tool name or arguments from model output; checking permissions only when the
job is created; running background work with the API key owner's full role; filtering only
citations while showing statements derived from restricted text; one shared "agent" identity with
every permission; counting denied tool requests as executed; limits enforced by prompting.

## 9. Scalability
Agents are stateless between iterations (state lives in the job's checkpoints and tables), so any
worker can run any job; kill-switch lookups are cached per organisation; evidence ids are local
to an agent run; findings and the trail are bounded per job (questions × findings, iterations ×
tool calls) and indexed by `(organization_id, job_id)`.

## 10. Next phases
Phase 15 adds verification beyond quotes (entailment), contradiction detection, a critic and
report composition and exports on top of `research_findings`. Phase 16 evaluates planner and
analyst prompts and models (including red-team injection cases) through the same gateway. Phase
19 adds an organisation-admin kill-switch API and approval rules for high-impact actions.

## 11. Acceptance criteria
- [x] A research job runs plan → collect → analyse with checkpoints (tested end to end offline;
  the Claude route uses the phase 11 adapter, tested against a mocked transport - the planner and
  analyst prompts have not yet been run against the live API).
- [x] No agent that reads untrusted content holds a side-effect tool (enforced in code and CI).
- [x] Only declared tools run; denied requests are recorded and audited, never executed.
- [x] Iteration, tool-call, cost and runtime limits end runs with typed reasons.
- [x] Kill switches stop agents, tools, providers and models within seconds; platform switches
  need the owner role; changes are audited.
- [x] A job never does more than its creator (or creating key) could do at that moment.
- [x] Expensive jobs, approval-only domains and evidence crossing the data policy wait for a
  human decision before anything is spent, fetched or sent.
- [x] Findings cite evidence that is verified mechanically; unsupported facts are downgraded.
- [x] Viewers never see statements, citations or tool arguments derived from evidence above their
  clearance.

## 12. How the specification maps to this design
The specification lists *possible* agents. Least privilege means a model is used only where
judgement is needed; everything that can be done deterministically is code.

| Specification agent | Here |
|---|---|
| Research Planner | `PLANNER` agent (objective only, no tools) + `normalise_plan` |
| Search, Web Research, Scraping | code: collect stage → search provider → SSRF-safe fetcher (phases 5-6) |
| Document, Data Extraction | code: sandboxed parsers and chunking (phases 7-8) |
| Analyst | `ANALYST` agent (one read-only tool) + mechanical citation checks |
| Verification, Contradiction, Critic, Report, Comparison | phase 15 |
| Entity Resolution | phase 18 (knowledge graph) |
| Monitoring | phase 17 |
| Security | code: injection assessment (phase 6), taint rule, catalogue, kill switches |

| Agent security control (spec §16) | Implementation |
|---|---|
| Identity, role | `AgentSpec.name` + versioned prompt; every run is an `agent_runs` row |
| Allowed tools / resources / data | `AgentSpec.tools` ∩ catalogue; the job's `SearchScope` (organisation, project, origins); the creator's classification ceiling and the gateway's data policy |
| Runtime, tool calls, token budget | `max_runtime_s`, `max_tool_calls`, `max_cost_usd` (+ per-route output-token caps and job/organisation budgets in the gateway) |
| Network access | none for agents; egress only through code (SSRF-safe fetcher) and the gateway |
| Iterations, recursion depth | `max_iterations`; depth is structurally 1 (agents never call agents) |
| Kill switches, audit, approvals | `kill_switches` (agent/tool/provider/model/all); audit log + `agent_runs`/`tool_calls`; crawl-scope, data-policy and cost approvals
