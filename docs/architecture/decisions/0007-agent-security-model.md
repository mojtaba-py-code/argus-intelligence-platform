# ADR 0007 - Plan-then-execute agents under least privilege

**Context.** An agent that reads attacker-controlled web pages and also holds powerful tools is the
canonical prompt-injection failure: the page tells the agent to use its tools.

**Decision.**

1. **Control flow comes from trusted input.** The planner sees only the user's objective and
   produces a schema-validated plan *before* any untrusted content is read. Code executes the plan.
2. **Agents are declarative specs** (`AgentSpec`): allowed tools, maximum iterations, tool calls,
   tokens, cost and runtime, network access, and the highest data classification they may see.
   The runtime enforces every limit; the model cannot change them.
3. **Taint rule.** An agent that ingests untrusted content never holds a tool with external side
   effects (sending e-mail or webhooks, writing outside its own job). A unit test checks this
   invariant across the whole agent catalogue.
4. **No agent calls another agent.** Only the orchestrator dispatches agents, so
   Agent → Tool → Agent loops cannot exist; recursion depth is structurally one.
5. **Tool calls are validated** against the tool's Pydantic schema and the agent's allow-list,
   recorded with redacted arguments, and subject to kill switches (global, organisation, agent,
   tool) and to human approval for high-impact actions.
6. **No arbitrary code or SQL.** `query_knowledge` takes typed filters; `analyze_data` takes a
   declarative, non-Turing-complete list of operations. Real code execution would be an external,
   isolated sandbox service behind the same interface and is disabled by default.

**Rejected.** Autonomous agents holding every tool; LLM-written SQL; in-process `exec` "sandboxes".

**Implementation notes (phases 12-14).**

* Tools are declared in `argus.modules.agents.catalogue` with their side-effect class; the runtime
  refuses undeclared or mis-declared tools, and the catalogue-wide taint test runs in CI.
* Agents request tools through typed fields of their structured output, mapped to requests by
  code (`AgentSpec.requests`) - never through free-form tool names.
* Web search and page fetching are **not** agent tools: the collect stage runs them from the
  plan, through the SSRF-safe fetcher and the organisation's domain policies. The analyst's only
  tool is `search_documents` (read-only, within the job's authorised scope).
* The data ceiling is enforced per job rather than per `AgentSpec`: the job acts for its creator,
  re-authorised at every stage, and the gateway's data policy applies to every call. Results are
  read with the viewer's rights; findings derived from evidence above the viewer's ceiling are
  withheld.
* Kill switches cover agents, tools, providers, models and everything, per organisation or
  platform-wide; platform switches are writable only by the owner role.
