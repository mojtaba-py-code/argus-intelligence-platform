"""Phases 12-14 units: the tool catalogue and taint rule, planning and analysis without a model."""

from __future__ import annotations

import importlib
import json
import pkgutil
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from pydantic import BaseModel

import argus.modules
from argus.core.classification import Classification
from argus.modules.agents.catalogue import TOOLS, ToolDeclaration
from argus.modules.agents.killswitch import InvalidSwitch, KillSwitchService
from argus.modules.agents.runtime import (
    AgentSpec,
    TaintViolation,
    ToolResult,
    ToolSpec,
    UndeclaredTool,
    check_declared,
    check_taint,
)
from argus.modules.knowledge.citations import EvidenceRegistry, quote_supported
from argus.modules.knowledge.retrieval import Hit
from argus.modules.llm.prompts import PromptRegistry
from argus.modules.llm.types import ProviderCall, UntrustedData
from argus.modules.research.analysis import ANALYST, FindingsOutput, local_analyst
from argus.modules.research.pipeline import StageFailed
from argus.modules.research.planning import (
    PLANNER,
    PlannedQuestion,
    PlanOutput,
    local_plan,
    normalise_plan,
)


def _agent_specs() -> list[AgentSpec]:
    """Every AgentSpec defined anywhere in the business modules."""
    found: dict[int, AgentSpec] = {}
    for info in pkgutil.walk_packages(argus.modules.__path__, "argus.modules."):
        module = importlib.import_module(info.name)
        for value in vars(module).values():
            if isinstance(value, AgentSpec):
                found[id(value)] = value
    return list(found.values())


class _Args(BaseModel):
    query: str


async def _noop(_: BaseModel) -> ToolResult:
    return ToolResult([])


def _tool(name: str, *, side_effects: bool) -> ToolSpec:
    return ToolSpec(name=name, input_model=_Args, side_effects=side_effects, handler=_noop)


def _spec(tools: set[str], *, reads_untrusted: bool) -> AgentSpec:
    return AgentSpec(
        name="probe",
        prompt="probe",
        output_model=_Args,
        tools=frozenset(tools),
        reads_untrusted=reads_untrusted,
    )


# --------------------------------------------------------------------- catalogue + taint
def test_every_agent_in_the_code_base_obeys_the_taint_rule_against_the_catalogue() -> None:
    specs = _agent_specs()
    names = [spec.name for spec in specs]
    assert {"planner", "analyst"} <= set(names)
    assert len(names) == len(set(names)), "agent names must be unique (metrics, kill switches)"
    registry = PromptRegistry.load()
    for spec in specs:
        check_taint(spec, TOOLS)  # unknown tools raise too
        assert spec.max_iterations >= 1
        assert spec.max_tool_calls >= 0
        assert Decimal(0) < spec.max_cost_usd <= Decimal(5)
        assert spec.max_runtime_s > 0
        template = registry.template(spec.prompt, registry.latest(spec.prompt))
        assert template.output_model is spec.output_model, spec.name
        # The prompt name is the routing task (data-policy approvals look routes up by it).
        assert template.spec.task == spec.prompt, spec.name
        # Agents with tools are told whether another round is possible; others are not.
        assert ("may_request_more" in template.spec.input_schema) == bool(spec.tools), spec.name


def test_agents_that_read_untrusted_text_hold_no_side_effect_tools() -> None:
    readers = [spec for spec in _agent_specs() if spec.reads_untrusted]
    assert ANALYST in readers
    for spec in readers:
        assert all(not TOOLS[name].side_effects for name in spec.tools), spec.name
    assert PLANNER.reads_untrusted is False
    assert PLANNER.tools == frozenset()


def test_taint_rule_refuses_side_effect_tools_for_untrusted_readers() -> None:
    tools = {
        "search_documents": _tool("search_documents", side_effects=False),
        "send_email": _tool("send_email", side_effects=True),
    }
    with pytest.raises(TaintViolation, match="send_email"):
        check_taint(_spec({"search_documents", "send_email"}, reads_untrusted=True), tools)
    # The same tool is fine for an agent that only sees trusted input.
    check_taint(_spec({"send_email"}, reads_untrusted=False), tools)
    with pytest.raises(ValueError, match="unknown tools"):
        check_taint(_spec({"delete_everything"}, reads_untrusted=False), tools)


def test_only_catalogued_tools_run_and_only_as_declared() -> None:
    check_declared({"search_documents": _tool("search_documents", side_effects=False)})
    with pytest.raises(UndeclaredTool):
        check_declared({"fetch_url": _tool("fetch_url", side_effects=False)})
    with pytest.raises(UndeclaredTool):  # implementation contradicts the declaration
        check_declared(
            {"search_documents": _tool("search_documents", side_effects=False)},
            {"search_documents": ToolDeclaration("search_documents", True, "x")},
        )
    with pytest.raises(UndeclaredTool):  # registered under another tool's name
        check_declared({"search_documents": _tool("other", side_effects=False)})


# ------------------------------------------------------------------------------ planning
def _plan(*questions: tuple[str, list[str]]) -> PlanOutput:
    return PlanOutput(
        summary="Summary\x00 with a NUL",
        questions=[
            PlannedQuestion(id=f"q{i}", question=q, search_queries=queries, rationale="r")
            for i, (q, queries) in enumerate(questions, start=1)
        ],
    )


def test_normalise_plan_dedupes_queries_enforces_the_budget_and_renumbers() -> None:
    plan = normalise_plan(
        _plan(
            ("Who leads the market?", ["market leaders", "Market Leaders", "market share"]),
            ("What changed in 2026?", ["market leaders", "news 2026"]),
            ("What are the risks?", ["risks", "criticism"]),
        ),
        max_queries=3,
    )
    assert [q.id for q in plan.questions] == ["q1", "q2", "q3"]
    assert plan.questions[0].search_queries == ["market leaders", "market share"]
    assert plan.questions[1].search_queries == ["news 2026"]
    # Budget exhausted: a question keeps its own wording as its only query.
    assert plan.questions[2].search_queries == ["What are the risks?"]
    assert "\x00" not in plan.summary


def test_normalise_plan_fails_typed_when_nothing_usable_remains() -> None:
    with pytest.raises(StageFailed) as caught:
        normalise_plan(_plan(("​​​​​", ["x y"])), max_queries=5)
    assert caught.value.code == "empty_plan"


def _call(task: str, variables: dict[str, Any], untrusted: list[UntrustedData]) -> ProviderCall:
    return ProviderCall(
        task=task,
        model="local/extractive",
        system="s",
        user="u",
        max_tokens=1000,
        output_model=None,
        effort=None,
        refusal_fallback=False,
        variables=variables,
        untrusted=tuple(untrusted),
    )


def test_local_plan_splits_compound_objectives_and_uses_angles_otherwise() -> None:
    compound = PlanOutput.model_validate_json(
        local_plan(
            _call(
                "research.plan",
                {
                    "objective": "Analyse the AI customer-support market and its leading vendors.",
                    "max_questions": 6,
                    "today": "2026-10-04",
                },
                [],
            )
        )
    )
    assert [q.question for q in compound.questions] == [
        "AI customer-support market?",
        "Its leading vendors?",
    ]
    single = PlanOutput.model_validate_json(
        local_plan(
            _call(
                "research.plan",
                {"objective": "Research quantum networking", "max_questions": 3, "today": "2026"},
                [],
            )
        )
    )
    assert len(single.questions) == 3
    assert "quantum networking 2026" in single.questions[0].search_queries


# ------------------------------------------------------------------------------ analysis
def _part(label: str, body: str, level: Classification = Classification.PUBLIC) -> UntrustedData:
    return UntrustedData(text=f"source: x\ntitle: t\n\n{body}", label=label, classification=level)


def test_local_analyst_quotes_the_best_sentence_per_evidence_block() -> None:
    output = FindingsOutput.model_validate_json(
        local_analyst(
            _call(
                "analysis.findings",
                {
                    "objective": "o",
                    "question": "Which vendors lead AI support?",
                    "may_request_more": True,
                },
                [
                    _part("E1", "The weather was mild. Vendor A leads AI support with 40% share."),
                    _part("E2", "Nothing relevant here at all."),
                ],
            )
        )
    )
    assert len(output.findings) == 1
    finding = output.findings[0]
    assert finding.evidence == ["E1"]
    assert finding.quote == "Vendor A leads AI support with 40% share."
    assert output.follow_up_queries == []
    assert output.insufficient_evidence is False


def test_local_analyst_asks_for_more_only_while_allowed() -> None:
    def run(may_request_more: bool) -> FindingsOutput:
        return FindingsOutput.model_validate_json(
            local_analyst(
                _call(
                    "analysis.findings",
                    {
                        "objective": "AI support vendors",
                        "question": "Which vendors lead?",
                        "may_request_more": may_request_more,
                    },
                    [],
                )
            )
        )

    assert run(True).follow_up_queries == ["AI support vendors"]
    last = run(False)
    assert (last.follow_up_queries, last.insufficient_evidence, last.findings) == ([], True, [])


def _hit(text: str, level: int, chunk: int) -> Hit:
    from uuid import UUID

    return Hit(
        chunk_id=UUID(int=chunk),
        origin="document",
        project_id=UUID(int=1),
        document_id=UUID(int=2),
        source_id=None,
        snapshot_id=None,
        ordinal=0,
        text=text,
        title="T",
        url=None,
        filename="f.pdf",
        page_start=1,
        page_end=1,
        char_start=0,
        char_end=len(text),
        classification=level,
        published_at=None,
        injection_level="none",
        score=1.0,
    )


def test_evidence_registry_ids_are_stable_unique_and_track_the_highest_classification() -> None:
    registry = EvidenceRegistry()
    first = registry.add([_hit("alpha text", 1, 1), _hit("beta text", 3, 2)])
    again = registry.add([_hit("alpha text", 1, 1), _hit("gamma text", 0, 3)])
    assert [p.label for p in first] == ["E1", "E2"]
    assert [p.label for p in again] == ["E3"]  # the duplicate chunk is not re-sent
    assert len(registry) == 3
    assert registry.max_classification is Classification.RESTRICTED
    assert EvidenceRegistry().max_classification is Classification.PUBLIC


def test_quotes_must_really_appear_in_the_cited_text() -> None:
    text = "Revenue grew 42%  year over year."
    assert quote_supported("revenue GREW 42% year over year", [text])
    assert not quote_supported("Revenue grew 50%", [text])
    assert not quote_supported("grew", [text])  # too short to prove anything


# -------------------------------------------------------------------------- kill switches
@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"kind": "everything", "target": "*"}, "kind must be"),
        ({"kind": "all", "target": "analyst"}, "must target"),
        ({"kind": "agent", "target": "Analyst; DROP"}, "target must be"),
        ({"kind": "agent", "target": "analyst", "reason": "x"}, "reason"),
        (
            {"kind": "agent", "target": "analyst", "expires_at": datetime.now(UTC) - timedelta(1)},
            "future",
        ),
    ],
)
async def test_kill_switch_input_is_validated_before_anything_is_written(
    kwargs: dict[str, Any], message: str
) -> None:
    class _Clock:
        def now(self) -> datetime:
            return datetime.now(UTC)

        def monotonic(self) -> float:
            return 0.0

    service = KillSwitchService(None, _Clock())  # type: ignore[arg-type]  # never reached
    arguments: dict[str, Any] = {"reason": "incident 42", "created_by": "oncall", **kwargs}
    with pytest.raises(InvalidSwitch, match=message):
        await service.engage(**arguments)


def test_findings_schema_is_strict() -> None:
    bad = {"findings": [], "follow_up_queries": [], "insufficient_evidence": True, "extra": 1}
    with pytest.raises(ValueError, match="extra"):
        FindingsOutput.model_validate_json(json.dumps(bad))
