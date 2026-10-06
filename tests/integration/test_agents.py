"""Phase 12 acceptance: the agent runtime against the real database.

The model is scripted (each iteration returns the next output), so these tests exercise exactly
what code decides: which tool requests run, what is recorded and audited, and how each limit and
kill switch ends a run.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID

import pytest
from pydantic import BaseModel, ConfigDict
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from argus.core.classification import Classification
from argus.core.config import Settings
from argus.infrastructure.db import Database
from argus.modules.agents.catalogue import ToolDeclaration
from argus.modules.agents.killswitch import KillSwitchService
from argus.modules.agents.runtime import (
    AgentContext,
    AgentRuntime,
    AgentSpec,
    TaintViolation,
    ToolRequest,
    ToolResult,
    ToolSpec,
    UndeclaredTool,
)
from argus.modules.llm.types import (
    CallContext,
    LLMRequest,
    LLMResult,
    LLMUnavailable,
    RenderedPrompt,
    UntrustedData,
)
from tests.support import ApiHarness, api_harness, create_org, register_and_login

pytestmark = pytest.mark.integration


class Step(BaseModel):
    """A scripted model output: which tools it asks for."""

    model_config = ConfigDict(extra="forbid")

    calls: list[tuple[str, dict[str, Any]]] = []


class LookupArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str


@dataclass
class ScriptedGateway:
    outputs: list[BaseModel | Exception]
    cost: Decimal = Decimal("0.10")
    requests: list[tuple[LLMRequest, CallContext]] = field(default_factory=list)

    async def generate(self, request: LLMRequest, context: CallContext) -> LLMResult:
        self.requests.append((request, context))
        output = self.outputs.pop(0) if self.outputs else Step()
        if isinstance(output, Exception):
            raise output
        return LLMResult(
            text=output.model_dump_json(),
            parsed=output,
            provider="scripted",
            model="scripted-model",
            served_model="scripted-model",
            locality="local",
            input_tokens=100,
            output_tokens=20,
            cost_usd=self.cost,
            latency_ms=1,
            attempts=(),
        )


class StaticPrompts:
    def __init__(self) -> None:
        self.rendered: list[dict[str, Any]] = []

    async def render(self, name: str, variables: dict[str, Any]) -> RenderedPrompt:
        self.rendered.append(dict(variables))
        return RenderedPrompt(
            name=name, version=3, sha256="0" * 64, task=name, system="system", user="user"
        )


CATALOGUE = {
    "lookup": ToolDeclaration("lookup", side_effects=False, description="read-only lookup"),
    "send_email": ToolDeclaration("send_email", side_effects=True, description="sends mail"),
}


def _requests(output: BaseModel) -> list[ToolRequest]:
    assert isinstance(output, Step)
    return [ToolRequest(tool, arguments) for tool, arguments in output.calls]


def reader(**limits: Any) -> AgentSpec:
    return AgentSpec(
        name="reader",
        prompt="test.reader",
        output_model=Step,
        tools=frozenset({"lookup"}),
        reads_untrusted=True,
        requests=_requests,
        **limits,
    )


@dataclass
class World:
    h: ApiHarness
    org_id: UUID
    gateway: ScriptedGateway
    prompts: StaticPrompts
    runtime: AgentRuntime
    lookups: list[str]

    def tools(self, *, classification: Classification = Classification.INTERNAL) -> Any:
        async def lookup(arguments: BaseModel) -> ToolResult:
            assert isinstance(arguments, LookupArgs)
            self.lookups.append(arguments.query)
            return ToolResult(
                [UntrustedData(f"result for {arguments.query}", "T1", classification)],
                {"query": arguments.query, "hits": 1},
            )

        return {
            "lookup": ToolSpec(
                name="lookup", input_model=LookupArgs, side_effects=False, handler=lookup
            )
        }

    async def run(
        self, spec: AgentSpec, outputs: list[BaseModel | Exception], **kwargs: Any
    ) -> Any:
        self.gateway.outputs = list(outputs)
        return await self.runtime.run(
            spec,
            variables={"question": "q"},
            evidence=[UntrustedData("seed evidence", "E1", Classification.PUBLIC)],
            tools=kwargs.pop("tools", None) or self.tools(),
            context=AgentContext(organization_id=self.org_id),
            **kwargs,
        )

    async def rows(self, sql: str, **params: Any) -> list[dict[str, Any]]:
        async with self.h.container.database.session(organization_id=self.org_id) as session:
            result = await session.execute(text(sql), params)
            return [dict(row._mapping) for row in result]


@pytest.fixture
async def world(db_settings: Settings) -> AsyncIterator[World]:
    async with api_harness(db_settings) as h:
        _, tokens = await register_and_login(h)
        org = await create_org(h, tokens["access_token"], "Agents Co")
        gateway = ScriptedGateway([])
        prompts = StaticPrompts()
        runtime = AgentRuntime(
            gateway=gateway,  # type: ignore[arg-type]
            prompts=prompts,  # type: ignore[arg-type]
            database=h.container.database,
            kill_switches=h.container.kill_switches,
            audit=h.container.audit,
            clock=h.container.clock,
            metrics=h.container.metrics,
            catalogue=CATALOGUE,
        )
        yield World(h, UUID(org["id"]), gateway, prompts, runtime, [])


# ------------------------------------------------------------------------ tool mediation
async def test_tool_requests_run_in_code_and_return_as_untrusted_data(world: World) -> None:
    outcome = await world.run(reader(), [Step(calls=[("lookup", {"query": "alpha"})]), Step()])
    assert (outcome.termination, outcome.iterations, outcome.tool_calls) == ("completed", 2, 1)
    assert world.lookups == ["alpha"]
    second, _ = world.gateway.requests[1]
    assert [part.label for part in second.untrusted] == ["E1", "T1"]  # fed back as data
    assert all(isinstance(part, UntrustedData) for part in second.untrusted)
    # The prompt is told whether another round is possible (False only on the last iteration).
    assert [v["may_request_more"] for v in world.prompts.rendered] == [True, True]
    assert outcome.prompts == ["test.reader@v3", "test.reader@v3"]

    run = (await world.rows("SELECT * FROM agent_runs WHERE id = :id", id=outcome.run_id))[0]
    assert (run["status"], run["iterations"], run["tool_calls"]) == ("completed", 2, 1)
    assert run["cost_usd"] == Decimal("0.200000")
    assert run["details"]["models"] == ["scripted-model", "scripted-model"]
    assert run["details"]["evidence_classification"] == int(Classification.INTERNAL)
    assert run["details"]["reads_untrusted"] is True
    calls = await world.rows("SELECT tool, outcome, arguments, result FROM tool_calls")
    assert calls == [
        {
            "tool": "lookup",
            "outcome": "ok",
            "arguments": {"query": "alpha"},
            "result": {"query": "alpha", "hits": 1},
        }
    ]
    # Every model call is tied to its run for cost attribution.
    assert {ctx.agent_run_id for _, ctx in world.gateway.requests} == {outcome.run_id}


async def test_tools_outside_the_allow_list_are_denied_recorded_and_audited(world: World) -> None:
    outcome = await world.run(
        reader(),
        [Step(calls=[("send_email", {"to": "attacker@example.com"}), ("shell", {})]), Step()],
    )
    assert outcome.termination == "completed"
    assert outcome.tool_calls == 0  # denied requests do not count as executed calls
    calls = await world.rows("SELECT tool, outcome, arguments FROM tool_calls ORDER BY tool")
    assert [(c["tool"], c["outcome"]) for c in calls] == [
        ("send_email", "denied"),
        ("shell", "denied"),
    ]
    audit = await world.rows(
        "SELECT action, outcome, details FROM audit_logs WHERE action = 'agent.tool_denied'"
    )
    assert {row["details"]["tool"] for row in audit} == {"send_email", "shell"}
    assert {row["outcome"] for row in audit} == {"failure"}


async def test_arguments_are_validated_before_the_handler_and_secrets_redacted(
    world: World,
) -> None:
    outcome = await world.run(
        reader(),
        [
            Step(
                calls=[
                    ("lookup", {"query": 7, "extra": True}),
                    ("lookup", {"query": "token sk-ant-api03-" + "x" * 40}),
                ]
            ),
            Step(),
        ],
    )
    assert outcome.termination == "completed"
    assert len(world.lookups) == 1  # only the valid request reached the handler
    calls = await world.rows("SELECT outcome, arguments FROM tool_calls ORDER BY created_at, id")
    assert [c["outcome"] for c in calls] == ["invalid_arguments", "ok"]
    assert "sk-ant-api03" not in str(calls[1]["arguments"])  # redacted at rest


# ------------------------------------------------------------------------------- limits
async def test_the_tool_call_limit_ends_the_run(world: World) -> None:
    step = Step(calls=[("lookup", {"query": "a"}), ("lookup", {"query": "b"})])
    outcome = await world.run(reader(max_tool_calls=1), [step, Step()])
    assert (outcome.termination, outcome.tool_calls) == ("max_tool_calls", 1)
    outcomes = [c["outcome"] for c in await world.rows("SELECT outcome FROM tool_calls")]
    assert sorted(outcomes) == ["limit", "ok"]


async def test_the_iteration_limit_ends_a_run_that_keeps_asking(world: World) -> None:
    asking = Step(calls=[("lookup", {"query": "again"})])
    outcome = await world.run(reader(max_iterations=2, max_tool_calls=10), [asking, asking])
    assert (outcome.termination, outcome.iterations) == ("max_iterations", 2)
    assert [v["may_request_more"] for v in world.prompts.rendered] == [True, False]


async def test_the_cost_cap_and_deadline_end_runs(world: World) -> None:
    asking = Step(calls=[("lookup", {"query": "q"})])
    spec = reader(max_iterations=5, max_tool_calls=10, max_cost_usd=Decimal("0.15"))
    outcome = await world.run(spec, [asking, asking, asking])
    assert (outcome.termination, outcome.iterations) == ("budget", 2)

    late = await world.run(reader(max_runtime_s=-1.0), [Step()])
    assert (late.termination, late.iterations) == ("timeout", 0)


async def test_a_failing_model_marks_the_run_failed(world: World) -> None:
    with pytest.raises(LLMUnavailable):
        await world.run(reader(), [LLMUnavailable("test.reader", (), "nothing configured")])
    runs = await world.rows("SELECT status, finished_at FROM agent_runs")
    assert runs[0]["status"] == "failed"
    assert runs[0]["finished_at"] is not None


# ------------------------------------------------------------------- catalogue and taint
async def test_taint_and_declarations_are_checked_before_anything_runs(world: World) -> None:
    async def send(_: BaseModel) -> ToolResult:
        raise AssertionError("must never run")

    risky = AgentSpec(
        name="mailer",
        prompt="test.mailer",
        output_model=Step,
        tools=frozenset({"send_email"}),
        reads_untrusted=True,
    )
    tools = {"send_email": ToolSpec("send_email", LookupArgs, side_effects=True, handler=send)}
    with pytest.raises(TaintViolation):
        await world.run(risky, [], tools=tools)
    lying = {"send_email": ToolSpec("send_email", LookupArgs, side_effects=False, handler=send)}
    with pytest.raises(UndeclaredTool):
        await world.run(risky, [], tools=lying)
    assert await world.rows("SELECT id FROM agent_runs") == []
    assert world.gateway.requests == []


# ------------------------------------------------------------------------ kill switches
async def test_kill_switches_stop_agents_and_tools(world: World) -> None:
    switches = world.h.container.kill_switches
    switch = await switches.engage(
        kind="agent",
        target="reader",
        reason="incident 7",
        created_by="oncall",
        organization_id=world.org_id,
    )
    stopped = await world.run(reader(), [Step()])
    assert (stopped.termination, stopped.iterations) == ("killed", 0)
    assert world.gateway.requests == []
    assert await switches.release(switch, released_by="oncall", organization_id=world.org_id)
    assert not await switches.release(switch, released_by="oncall", organization_id=world.org_id)

    await switches.engage(
        kind="tool",
        target="lookup",
        reason="tool misbehaving",
        created_by="oncall",
        organization_id=world.org_id,
        expires_at=world.h.clock.now() + timedelta(hours=1),
    )
    outcome = await world.run(reader(), [Step(calls=[("lookup", {"query": "x"})]), Step()])
    assert outcome.termination == "completed"
    assert world.lookups == []
    assert [c["outcome"] for c in await world.rows("SELECT outcome FROM tool_calls")] == ["killed"]
    actions = [
        row["action"]
        for row in await world.rows(
            "SELECT action FROM audit_logs WHERE target_type = 'kill_switch' ORDER BY chain_seq"
        )
    ]
    assert actions == ["kill_switch.engaged", "kill_switch.released", "kill_switch.engaged"]


async def test_platform_switches_need_the_owner_role_and_apply_to_every_organisation(
    world: World, db_settings: Settings
) -> None:
    with pytest.raises(DBAPIError):  # the runtime role cannot write platform-wide rows (RLS)
        await world.h.container.kill_switches.engage(
            kind="all", target="*", reason="global stop", created_by="attacker"
        )
    owner = Database(
        db_settings.database.model_copy(update={"url": db_settings.database.migration_url}),
        application_name="argus-test-owner",
    )
    operator = KillSwitchService(owner, world.h.clock, audit=world.h.container.audit)
    switch = await operator.engage(
        kind="all", target="*", reason="global stop", created_by="operator"
    )
    try:
        world.h.container.kill_switches.forget()
        stopped = await world.run(reader(), [Step()])
        assert stopped.termination == "killed"
        platform = [s for s in await operator.list_switches() if s.organization_id is None]
        assert [(s.id, s.kind, s.target, s.active) for s in platform] == [
            (switch, "all", "*", True)
        ]
        # A tenant can see the platform switch but cannot release it (RLS filters the UPDATE).
        assert not await world.h.container.kill_switches.release(
            switch, released_by="tenant", organization_id=world.org_id
        )
        assert await operator.release(switch, released_by="operator")
        world.h.container.kill_switches.forget()
        assert (await world.run(reader(), [Step()])).termination == "completed"
    finally:
        await operator.release(switch, released_by="test cleanup")  # never leak a global stop
        world.h.container.kill_switches.forget()
        await owner.dispose()
