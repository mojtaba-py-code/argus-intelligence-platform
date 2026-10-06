"""Phase 12 - the research planner.

The planner sees **only the user's objective** - no web pages, no documents - and returns a
bounded, schema-validated plan: sub-questions, each with a few search queries. Control flow comes
from this trusted plan; everything read later is data (ADR 0007). The plan is normalised by code
(limits, duplicates, sanitising) before anything acts on it, and stored as a versioned
``research_plans`` row.
"""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Annotated, Any, Final

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from argus.core.classification import Classification
from argus.modules.agents.runtime import AgentContext, AgentSpec
from argus.modules.llm.types import ProviderCall
from argus.modules.research.creator import creator_access
from argus.modules.research.models import ResearchPlan
from argus.modules.research.pipeline import ApprovalRequired, StageContext, StageFailed
from argus.security.text import clean_line

MAX_QUESTIONS: Final = 8
Query = Annotated[str, Field(min_length=2, max_length=200)]


class PlannedQuestion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^q[1-9][0-9]?$")
    question: str = Field(min_length=5, max_length=300)
    search_queries: list[Query] = Field(min_length=1, max_length=4)
    rationale: str = Field(max_length=500)


class PlanOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(max_length=1000)
    questions: list[PlannedQuestion] = Field(min_length=1, max_length=MAX_QUESTIONS)
    out_of_scope: list[Annotated[str, Field(max_length=300)]] = Field(
        default_factory=list, max_length=5
    )


PLANNER: Final = AgentSpec(
    name="planner",
    prompt="research.plan",
    output_model=PlanOutput,
    tools=frozenset(),
    reads_untrusted=False,
    max_iterations=1,
    max_tool_calls=0,
)


def normalise_plan(plan: PlanOutput, *, max_queries: int) -> PlanOutput:
    """Code, not the model, enforces the plan's bounds: unique ids, sanitised text, query budget."""
    questions: list[PlannedQuestion] = []
    seen_queries: set[str] = set()
    budget = max_queries
    for index, item in enumerate(plan.questions[:MAX_QUESTIONS], start=1):
        queries: list[str] = []
        for raw in item.search_queries:
            query = clean_line(raw, 200)
            if query and query.casefold() not in seen_queries and budget > 0:
                seen_queries.add(query.casefold())
                queries.append(query)
                budget -= 1
        question = clean_line(item.question, 300)
        if not question:
            continue
        if not queries:  # every sub-question keeps at least its own wording as a query
            queries = [question[:200]]
        questions.append(
            PlannedQuestion(
                id=f"q{index}",
                question=question,
                search_queries=queries,
                rationale=clean_line(item.rationale, 500) or "",
            )
        )
    if not questions:
        raise StageFailed("empty_plan", "The planner produced no usable research questions.")
    return PlanOutput(
        summary=clean_line(plan.summary, 1000) or "",
        questions=questions,
        out_of_scope=[
            line for line in (clean_line(item, 300) for item in plan.out_of_scope) if line
        ],
    )


# ------------------------------------------------------------------ offline implementation
_LEADING_VERB: Final = re.compile(
    r"^(please\s+)?(analy[sz]e|research|assess|compare|investigate|evaluate|study|review|"
    r"identify|examine|explore|summari[sz]e|map|find|determine)\s+(the\s+)?",
    re.IGNORECASE,
)
_SPLIT: Final = re.compile(
    r"[.;?!]\s+|\s+and\s+(?=(?:its|their|the|how|what|which|who)\b)", re.IGNORECASE
)
_ANGLES: Final = (
    ("What is the current state of {topic}?", ["{topic} overview", "{topic} {year}"]),
    (
        "Who are the main organisations or players in {topic}?",
        ["{topic} leading companies", "{topic} market share"],
    ),
    ("What recent developments affect {topic}?", ["{topic} news {year}", "{topic} recent changes"]),
    (
        "What risks, criticisms or open problems exist for {topic}?",
        ["{topic} risks", "{topic} criticism"],
    ),
)


def local_plan(call: ProviderCall) -> str:
    """Deterministic planner: sub-questions from the objective's clauses or standard angles."""
    objective = str(call.variables.get("objective", "")).strip()
    year = str(call.variables.get("today", ""))[:4]
    max_questions = int(call.variables.get("max_questions", 4))
    topic = _LEADING_VERB.sub("", objective).strip(" .") or objective
    clauses = [part.strip(" .") for part in _SPLIT.split(topic) if len(part.strip(" .")) > 8]
    questions: list[PlannedQuestion] = []
    if len(clauses) > 1:
        for clause in clauses[:max_questions]:
            words = " ".join(clause.split()[:10])
            questions.append(
                PlannedQuestion(
                    id=f"q{len(questions) + 1}",
                    question=clause[0].upper() + clause[1:] + ("" if clause.endswith("?") else "?"),
                    search_queries=[words[:200]],
                    rationale="A distinct part of the objective.",
                )
            )
    else:
        short = " ".join(topic.split()[:8])
        for template, queries in _ANGLES[:max_questions]:
            questions.append(
                PlannedQuestion(
                    id=f"q{len(questions) + 1}",
                    question=template.format(topic=short),
                    search_queries=[
                        query.format(topic=short, year=year).strip()[:200] for query in queries
                    ],
                    rationale="A standard angle for a single-topic objective.",
                )
            )
    return PlanOutput(
        summary=f"Research plan for: {objective[:900]}",
        questions=questions,
        out_of_scope=[],
    ).model_dump_json()


# --------------------------------------------------------------------------- the stage
class PlanStage:
    key = "plan"
    weight = 1

    async def run(self, ctx: StageContext) -> dict[str, Any]:
        services = ctx.services
        settings = services.settings.research
        access = await creator_access(ctx)  # a creator who lost access must not spend budget
        # The organisation may lower the platform's approval threshold, never raise it.
        threshold = Decimal(
            str(
                min(
                    access.org.settings.budgets.approval_threshold_usd,
                    settings.approval_cost_threshold_usd,
                )
            )
        )
        if ctx.job.budget_usd > threshold and "cost_threshold" not in ctx.approvals:
            raise ApprovalRequired(
                "cost_threshold",
                f"The job's budget (${ctx.job.budget_usd:.2f}) is above the approval threshold "
                f"(${threshold:.2f}).",
                {"budget_usd": str(ctx.job.budget_usd), "threshold_usd": str(threshold)},
            )
        outcome = await services.agents.run(
            PLANNER,
            variables={
                "objective": ctx.job.objective,
                "mode": ctx.job.mode,
                "max_questions": min(MAX_QUESTIONS, 6),
                "max_queries": settings.max_queries_per_job,
                "today": services.clock.now().date().isoformat(),
            },
            evidence=(),
            tools={},
            context=AgentContext(
                organization_id=ctx.job.organization_id,
                job_id=ctx.job.id,
                approved_external="data_policy" in ctx.approvals,
            ),
            classification=Classification.INTERNAL,
        )
        if outcome.termination == "killed":
            raise StageFailed("agent_disabled", "An administrator has stopped the planner agent.")
        if not isinstance(outcome.output, PlanOutput):
            raise StageFailed("plan_failed", "The planner did not produce a valid plan.")
        plan = normalise_plan(outcome.output, max_queries=settings.max_queries_per_job)
        async with services.database.tenant(ctx.scope) as session:
            version = (
                await session.execute(
                    select(func.coalesce(func.max(ResearchPlan.version), 0)).where(
                        ResearchPlan.job_id == ctx.job.id
                    )
                )
            ).scalar_one() + 1
            session.add(
                ResearchPlan(
                    organization_id=ctx.job.organization_id,
                    job_id=ctx.job.id,
                    version=version,
                    plan=plan.model_dump(mode="json"),
                    model=outcome.models[-1] if outcome.models else None,
                    prompt_version=outcome.prompts[-1] if outcome.prompts else None,
                )
            )
        return {
            "version": version,
            "questions": [question.model_dump(mode="json") for question in plan.questions],
            "agent_run_id": str(outcome.run_id),
        }
