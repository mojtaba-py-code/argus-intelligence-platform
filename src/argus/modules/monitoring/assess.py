"""The monitoring agent: is a detected change meaningful, and what is it about?

It reads the changed lines of a public page (untrusted text) and holds no tools. Code computed a
significance score first; the agent's judgement is averaged with it, never replaces it, and its
summary is sanitised, defanged and dropped if it reads as an instruction.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated, Final, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field

from argus.core.classification import Classification
from argus.modules.agents.runtime import AgentSpec
from argus.modules.llm.types import ProviderCall, UntrustedData
from argus.modules.monitoring.diff import Diff, significance
from argus.modules.research.reporting import prose
from argus.security.injection import instruction_like

Topic = Literal["product", "pricing", "website", "people", "jobs", "news", "funding", "technology"]
TOPIC_NAMES: Final = frozenset(get_args(Topic))
MEANINGFUL_AT: Final = 0.5


class ChangeAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meaningful: bool
    significance: float = Field(ge=0, le=1)
    topics: list[Topic] = Field(default_factory=list, max_length=4)
    summary: Annotated[str, Field(max_length=300)]


MONITOR_ASSESSOR: Final = AgentSpec(
    name="monitor_assessor",
    prompt="monitor.assess",
    output_model=ChangeAssessment,
    tools=frozenset(),
    reads_untrusted=True,
    max_iterations=1,
    max_tool_calls=0,
    max_cost_usd=Decimal("0.10"),
)


def change_block(url: str, change: Diff) -> UntrustedData:
    excerpt = change.excerpt()
    lines = [f"URL: {url}", "ADDED:"]
    lines += [f"+ {line}" for line in excerpt["added"]] or ["(nothing)"]
    lines.append("REMOVED:")
    lines += [f"- {line}" for line in excerpt["removed"]] or ["(nothing)"]
    return UntrustedData(
        text="\n".join(lines), label="CHANGE", classification=Classification.PUBLIC
    )


def extractive_summary(change: Diff) -> str:
    if change.added:
        text = f"Added: {change.added[0]}"
    elif change.removed:
        text = f"Removed: {change.removed[0]}"
    else:
        text = "No visible change."
    summary = prose(text, 300)
    return summary if not instruction_like(summary) else "The page changed (content withheld)."


def safe_summary(assessment: ChangeAssessment | None, change: Diff) -> str:
    """The model's summary when it is safe to show, otherwise an extractive one."""
    if assessment is not None:
        summary = prose(assessment.summary, 300)
        if summary and not instruction_like(summary):
            return summary
    return extractive_summary(change)


def combined(code_score: float, assessment: ChangeAssessment | None) -> float:
    if assessment is None:
        return code_score
    judged = assessment.significance if assessment.meaningful else 0.0
    return round(0.5 * code_score + 0.5 * judged, 3)


# ------------------------------------------------------------------ offline implementation
def local_assessor(call: ProviderCall) -> str:
    """Deterministic judge: the code rubric applied to the excerpt it was given."""
    added: list[str] = []
    removed: list[str] = []
    for part in call.untrusted:
        for line in part.text.split("\n"):
            if line.startswith("+ "):
                added.append(line[2:])
            elif line.startswith("- "):
                removed.append(line[2:])
    topics = [str(t) for t in call.variables.get("topics", [])]
    change = Diff(tuple(added), tuple(removed), 0.0)
    score, matched = significance(change, topics)
    return ChangeAssessment.model_validate(
        {
            "meaningful": score >= MEANINGFUL_AT,
            "significance": score,
            "topics": [t for t in matched if t in TOPIC_NAMES][:4],
            "summary": extractive_summary(change),
        }
    ).model_dump_json()
