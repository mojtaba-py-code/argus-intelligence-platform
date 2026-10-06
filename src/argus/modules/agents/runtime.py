"""The agent runtime: models propose, code disposes (ADR 0007).

An agent is a declarative :class:`AgentSpec` - prompt, output schema, allowed tools, limits. The
model never calls anything itself: its structured output may *request* tools, and this runtime
decides. Per request it checks the allow-list, the kill switches and the limits, validates the
arguments against the tool's Pydantic model, runs the tool, records the call (arguments redacted)
and feeds the result back as **untrusted data** on the next iteration. Denied requests are
recorded and audited, never executed.

Invariants enforced in code, not by prompting:

* **Declared tools only** - every tool is declared in :mod:`argus.modules.agents.catalogue`;
  a tool missing from it, or contradicting its declared side-effect class, is refused.
* **Taint rule** - an agent that reads untrusted content cannot be given a tool with side
  effects (changing state outside the job, or sending data out of the platform). Checked when
  a run starts, and across the whole catalogue by a unit test.
* **No agent calls an agent** - tools are plain functions; only the orchestrator runs agents.
* **Hard limits** - iterations, tool calls, cost and wall-clock time, each ending the run with a
  typed termination reason.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID

from opentelemetry.trace import Status, StatusCode
from pydantic import BaseModel, ValidationError
from sqlalchemy import type_coerce, update
from sqlalchemy.dialects.postgresql import JSONB

from argus.core.classification import Classification
from argus.core.clock import Clock
from argus.core.ids import uuid7
from argus.core.logging import get_logger
from argus.core.redaction import redact
from argus.core.scope import Actor, TenantScope
from argus.infrastructure.db import Database
from argus.infrastructure.observability.metrics import Metrics
from argus.infrastructure.observability.tracing import set_attributes, span
from argus.modules.agents.catalogue import TOOLS, ToolDeclaration
from argus.modules.agents.killswitch import KillSwitchService
from argus.modules.agents.models import AgentRun, ToolCallRecord
from argus.modules.audit.service import AuditCategory, AuditEvent, AuditOutcome, AuditService
from argus.modules.llm.deployments import PromptService
from argus.modules.llm.gateway import LLMGateway
from argus.modules.llm.types import CallContext, LLMRequest, UntrustedData

log = get_logger(__name__)
Termination = Literal[
    "completed", "max_iterations", "max_tool_calls", "budget", "timeout", "killed", "failed"
]


class TaintViolation(ValueError):
    """An agent that reads untrusted content was given a side-effecting tool."""


class UndeclaredTool(ValueError):
    """A tool that is not in the catalogue, or that contradicts its declaration."""


@dataclass(frozen=True)
class ToolRequest:
    tool: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ToolResult:
    parts: list[UntrustedData]
    """What the agent sees next: always untrusted data, never instructions."""
    summary: dict[str, Any] = field(default_factory=dict)
    """Small, recorded in ``tool_calls.result``."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    input_model: type[BaseModel]
    side_effects: bool
    """True if the tool changes state outside the job or sends data out of the platform."""
    handler: Callable[[BaseModel], Awaitable[ToolResult]]
    description: str = ""


@dataclass(frozen=True)
class AgentSpec:
    name: str
    prompt: str
    output_model: type[BaseModel]
    tools: frozenset[str]
    reads_untrusted: bool
    max_iterations: int = 3
    max_tool_calls: int = 4
    max_cost_usd: Decimal = Decimal("1.00")
    max_runtime_s: float = 300.0
    requests: Callable[[BaseModel], list[ToolRequest]] = field(default=lambda _: [])
    """Extracts tool requests from a (validated) output; none means the output is final."""


@dataclass(frozen=True)
class AgentContext:
    organization_id: UUID
    job_id: UUID | None = None
    approved_external: bool = False


@dataclass
class AgentOutcome:
    run_id: UUID
    output: BaseModel | None
    termination: Termination
    iterations: int
    tool_calls: int
    cost_usd: Decimal
    evidence: list[UntrustedData]
    tool_summaries: list[dict[str, Any]]
    models: list[str] = field(default_factory=list)
    """The model that served each iteration (after any fallback)."""
    prompts: list[str] = field(default_factory=list)
    """``name@vN`` of the prompt rendered for each iteration."""


def check_taint(spec: AgentSpec, tools: Mapping[str, ToolSpec | ToolDeclaration]) -> None:
    unknown = spec.tools - set(tools)
    if unknown:
        msg = f"agent {spec.name!r} lists unknown tools {sorted(unknown)}"
        raise ValueError(msg)
    risky = sorted(name for name in spec.tools if tools[name].side_effects)
    if spec.reads_untrusted and risky:
        msg = f"agent {spec.name!r} reads untrusted data and may not hold side-effect tools {risky}"
        raise TaintViolation(msg)


def check_declared(
    tools: Mapping[str, ToolSpec], catalogue: Mapping[str, ToolDeclaration] = TOOLS
) -> None:
    """Only catalogued tools run, under their own name and their declared side-effect class."""
    for key, tool in tools.items():
        declared = catalogue.get(key)
        if declared is None or tool.name != key or tool.side_effects != declared.side_effects:
            msg = f"tool {key!r} is not declared in the catalogue as implemented"
            raise UndeclaredTool(msg)


class AgentRuntime:
    def __init__(
        self,
        *,
        gateway: LLMGateway,
        prompts: PromptService,
        database: Database,
        kill_switches: KillSwitchService,
        audit: AuditService,
        clock: Clock,
        metrics: Metrics,
        catalogue: Mapping[str, ToolDeclaration] = TOOLS,
    ) -> None:
        self._catalogue = catalogue
        self._gateway = gateway
        self._prompts = prompts
        self._db = database
        self._kill = kill_switches
        self._audit = audit
        self._clock = clock
        self._metrics = metrics

    async def run(
        self,
        spec: AgentSpec,
        *,
        variables: dict[str, Any],
        evidence: Sequence[UntrustedData],
        tools: Mapping[str, ToolSpec],
        context: AgentContext,
        classification: Classification = Classification.INTERNAL,
    ) -> AgentOutcome:
        check_declared(tools, self._catalogue)
        check_taint(spec, tools)
        scope = TenantScope(context.organization_id, Actor.system())
        with span(
            f"agent.run {spec.name}",
            attributes={
                "argus.agent": spec.name,
                "argus.job.id": context.job_id,
                "argus.organization.id": context.organization_id,
            },
        ) as current:
            run_id = await self._start(scope, spec, context)
            outcome = AgentOutcome(run_id, None, "failed", 0, 0, Decimal(0), list(evidence), [])
            deadline = time.monotonic() + spec.max_runtime_s
            try:
                outcome.termination = await self._loop(
                    spec, variables, tools, context, classification, outcome, deadline
                )
            except Exception:
                outcome.termination = "failed"
                raise
            finally:
                await self._finish(scope, outcome)
                self._metrics.agent_runs.labels(spec.name, outcome.termination).inc()
                set_attributes(
                    current,
                    {
                        "argus.agent_run.id": run_id,
                        "argus.agent.termination": outcome.termination,
                        "argus.agent.iterations": outcome.iterations,
                        "argus.agent.tool_calls": outcome.tool_calls,
                        "argus.agent.cost_usd": float(outcome.cost_usd),
                    },
                )
        return outcome

    async def _loop(
        self,
        spec: AgentSpec,
        variables: dict[str, Any],
        tools: Mapping[str, ToolSpec],
        context: AgentContext,
        classification: Classification,
        outcome: AgentOutcome,
        deadline: float,
    ) -> Termination:
        for iteration in range(spec.max_iterations):
            if await self._kill.blocked(context.organization_id, "agent", spec.name):
                return "killed"
            if time.monotonic() > deadline:
                return "timeout"
            if outcome.cost_usd >= spec.max_cost_usd:
                return "budget"
            last = iteration == spec.max_iterations - 1
            # Agents that may request tools are told whether another round is still possible
            # (their prompts declare ``may_request_more``); tool-less agents get no extra variable.
            extra = {"may_request_more": not last} if spec.tools else {}
            prompt = await self._prompts.render(spec.prompt, {**variables, **extra})
            result = await self._gateway.generate(
                LLMRequest(
                    prompt=prompt,
                    untrusted=tuple(outcome.evidence),
                    classification=classification,
                ),
                CallContext(
                    organization_id=context.organization_id,
                    job_id=context.job_id,
                    agent_run_id=outcome.run_id,
                    approved_external=context.approved_external,
                ),
            )
            outcome.iterations += 1
            outcome.cost_usd += result.cost_usd
            outcome.models.append(result.served_model)
            outcome.prompts.append(f"{prompt.name}@v{prompt.version}")
            outcome.output = result.parsed
            requests = spec.requests(result.parsed) if result.parsed is not None else []
            if not requests:
                return "completed"
            if last:
                return "max_iterations"
            for request in requests:
                if outcome.tool_calls >= spec.max_tool_calls:
                    await self._record_tool(spec, context, outcome, request, "limit", {})
                    return "max_tool_calls"
                await self._call_tool(spec, tools, request, context, outcome)
        return "max_iterations"

    async def _call_tool(
        self,
        spec: AgentSpec,
        tools: Mapping[str, ToolSpec],
        request: ToolRequest,
        context: AgentContext,
        outcome: AgentOutcome,
    ) -> None:
        # The requested name comes from model output: only declared names become span names.
        name = request.tool if request.tool in self._catalogue else "undeclared"
        with span(f"agent.tool {name}", attributes={"argus.tool": name}) as current:
            result = await self._call_tool_unsafe_name(spec, tools, request, context, outcome)
            current.set_attribute("argus.tool.outcome", result)
            if result != "ok":
                current.set_status(Status(StatusCode.ERROR, result))

    async def _call_tool_unsafe_name(
        self,
        spec: AgentSpec,
        tools: Mapping[str, ToolSpec],
        request: ToolRequest,
        context: AgentContext,
        outcome: AgentOutcome,
    ) -> str:
        if request.tool not in spec.tools or request.tool not in tools:
            await self._record_tool(spec, context, outcome, request, "denied", {})
            await self._audit.record_detached(
                AuditEvent(
                    action="agent.tool_denied",
                    category=AuditCategory.AGENT,
                    actor=Actor.system(),
                    outcome=AuditOutcome.FAILURE,
                    organization_id=context.organization_id,
                    target_type="agent_run",
                    target_id=str(outcome.run_id),
                    details={"agent": spec.name, "tool": request.tool[:64]},
                )
            )
            log.warning("agent.tool_denied", agent=spec.name, tool=request.tool[:64])
            return "denied"
        if await self._kill.blocked(context.organization_id, "tool", request.tool):
            await self._record_tool(spec, context, outcome, request, "killed", {})
            return "killed"
        tool = tools[request.tool]
        try:
            arguments = tool.input_model.model_validate(request.arguments)
        except ValidationError:
            await self._record_tool(spec, context, outcome, request, "invalid_arguments", {})
            return "invalid_arguments"
        started = time.monotonic()
        try:
            result = await tool.handler(arguments)
        except Exception:
            log.exception("agent.tool_failed", agent=spec.name, tool=tool.name)
            await self._record_tool(spec, context, outcome, request, "error", {}, started=started)
            return "error"
        outcome.evidence.extend(result.parts)
        outcome.tool_summaries.append({"tool": tool.name, **result.summary})
        await self._record_tool(
            spec, context, outcome, request, "ok", result.summary, started=started
        )
        return "ok"

    # ------------------------------------------------------------------- records
    async def _start(self, scope: TenantScope, spec: AgentSpec, context: AgentContext) -> UUID:
        run_id = uuid7()
        async with self._db.tenant(scope) as session:
            session.add(
                AgentRun(
                    id=run_id,
                    organization_id=context.organization_id,
                    job_id=context.job_id,
                    agent=spec.name,
                    status="running",
                    details={"tools": sorted(spec.tools), "reads_untrusted": spec.reads_untrusted},
                )
            )
        return run_id

    async def _finish(self, scope: TenantScope, outcome: AgentOutcome) -> None:
        async with self._db.tenant(scope) as session:
            await session.execute(
                update(AgentRun)
                .where(AgentRun.id == outcome.run_id)
                .values(
                    status=outcome.termination,
                    iterations=outcome.iterations,
                    tool_calls=outcome.tool_calls,
                    cost_usd=outcome.cost_usd,
                    finished_at=self._clock.now(),
                    updated_at=self._clock.now(),
                    details=AgentRun.details.op("||")(
                        type_coerce(
                            {
                                "evidence_classification": max(
                                    (int(part.classification) for part in outcome.evidence),
                                    default=0,
                                ),
                                "models": outcome.models[-5:],
                                "prompts": outcome.prompts[-5:],
                            },
                            JSONB,
                        )
                    ),
                )
            )

    async def _record_tool(
        self,
        spec: AgentSpec,
        context: AgentContext,
        outcome: AgentOutcome,
        request: ToolRequest,
        result: str,
        summary: dict[str, Any],
        *,
        started: float | None = None,
    ) -> None:
        if result in {"ok", "error"}:
            outcome.tool_calls += 1
        self._metrics.tool_calls.labels(spec.name, request.tool[:64], result).inc()
        async with self._db.tenant(TenantScope(context.organization_id, Actor.system())) as session:
            session.add(
                ToolCallRecord(
                    organization_id=context.organization_id,
                    agent_run_id=outcome.run_id,
                    tool=request.tool[:64],
                    outcome=result,
                    arguments=redact(dict(request.arguments)),
                    result=redact(summary),
                    latency_ms=int((time.monotonic() - started) * 1000) if started else 0,
                )
            )
