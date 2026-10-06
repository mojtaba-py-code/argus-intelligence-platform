"""Phase 15 - contradiction detection: when sources disagree, say so and say why.

1. **Candidates (code).** Pairs of included findings from *different* sources that talk about the
   same thing (shared vocabulary) but differ in their figures or in polarity.
2. **Judgement (agent).** The contradiction judge decides whether each pair really conflicts,
   names the attribute, and offers an explanation: different time periods, different scope or
   definitions, source reliability, measurement or estimate, or unresolved.
3. **Justification (code).** A preference for one side is kept only when code can verify its
   stated reason - the preferred source really is newer, or really is markedly more reliable.
   Otherwise the platform prefers neither and presents the uncertainty. It never silently picks
   a value.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from itertools import combinations
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete

from argus.core.classification import Classification
from argus.modules.agents.runtime import AgentContext, AgentSpec
from argus.modules.llm.types import ProviderCall, UntrustedData
from argus.modules.research.creator import creator_access
from argus.modules.research.evidence import (
    FindingRecord,
    content_terms,
    load_job_evidence,
    negated,
    numbers,
)
from argus.modules.research.models import ResearchContradiction
from argus.modules.research.pipeline import StageContext, StageFailed
from argus.modules.research.verification import INCLUDED
from argus.security.text import clean_line

Explanation = Literal[
    "different_time_periods",
    "different_scope_or_definition",
    "source_reliability",
    "measurement_or_estimate",
    "unresolved",
]
Preference = Literal["a", "b", "neither"]
MAX_PAIRS: Final = 20
BATCH: Final = 10
MIN_SHARED_TERMS: Final = 2
MIN_SIMILARITY: Final = 0.25
RELIABILITY_MARGIN: Final = 0.2
"""How much more reliable a source must be before reliability can justify preferring it."""


class PairJudgement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pair: str = Field(pattern=r"^P[1-9][0-9]?$")
    contradiction: bool
    attribute: str = Field(max_length=120)
    explanation: Explanation
    rationale: str = Field(max_length=400)
    preferred: Preference


class ContradictionOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    judgements: list[PairJudgement] = Field(max_length=MAX_PAIRS)


CONTRADICTION_JUDGE: Final = AgentSpec(
    name="contradiction_judge",
    prompt="verification.contradictions",
    output_model=ContradictionOutput,
    tools=frozenset(),
    reads_untrusted=True,
    max_iterations=1,
    max_tool_calls=0,
    max_cost_usd=Decimal("0.50"),
)


@dataclass(frozen=True)
class Candidate:
    label: str
    a: FindingRecord
    b: FindingRecord
    similarity: float
    shared: tuple[str, ...]


# ------------------------------------------------------------------------- candidates
def candidate_pairs(findings: Sequence[FindingRecord]) -> list[Candidate]:
    eligible = [f for f in findings if f.support in INCLUDED and f.parents]
    found: list[tuple[float, tuple[str, ...], FindingRecord, FindingRecord]] = []
    for a, b in combinations(eligible, 2):
        if a.parents & b.parents:  # the same source cannot contradict itself here
            continue
        terms_a, terms_b = content_terms(a.statement), content_terms(b.statement)
        shared = terms_a & terms_b
        if len(shared) < MIN_SHARED_TERMS:
            continue
        similarity = len(shared) / len(terms_a | terms_b)
        if similarity < MIN_SIMILARITY:
            continue
        figures_a, figures_b = numbers(a.statement), numbers(b.statement)
        figures_differ = bool(figures_a and figures_b and figures_a != figures_b)
        if figures_differ or negated(a.statement) != negated(b.statement):
            found.append((similarity, tuple(sorted(shared)), a, b))
    found.sort(key=lambda item: -item[0])
    return [
        Candidate(f"P{index}", a, b, round(similarity, 3), shared)
        for index, (similarity, shared, a, b) in enumerate(found[:MAX_PAIRS], start=1)
    ]


def _describe(finding: FindingRecord) -> str:
    source = finding.citations[0].source
    published = finding.newest_publication
    reliability = (
        f"{finding.best_reputation:.2f} ({source.trust_tier})"
        if finding.best_reputation is not None
        else "internal document"
        if source.origin == "document"
        else "unknown"
    )
    return (
        f"{finding.statement}\n"
        f"   source: {source.label}; published: "
        f"{published.date().isoformat() if published else 'unknown'}; reliability: {reliability}\n"
        f"   quote: {' '.join(finding.citations[0].quote.split())}"
    )


def pair_block(candidate: Candidate) -> UntrustedData:
    return UntrustedData(
        text=f"A: {_describe(candidate.a)}\nB: {_describe(candidate.b)}",
        label=candidate.label,
        classification=Classification(max(candidate.a.classification, candidate.b.classification)),
    )


def justified(candidate: Candidate, explanation: str, preferred: Preference) -> Preference:
    """Keep a preference only when its stated reason holds in the metadata."""
    if preferred == "neither":
        return "neither"
    chosen, other = (candidate.a, candidate.b) if preferred == "a" else (candidate.b, candidate.a)
    if explanation == "different_time_periods":
        newer, older = chosen.newest_publication, other.newest_publication
        if newer is not None and older is not None and newer > older:
            return preferred
    if explanation == "source_reliability":
        mine, theirs = chosen.best_reputation, other.best_reputation
        if mine is not None and theirs is not None and mine - theirs >= RELIABILITY_MARGIN:
            return preferred
    return "neither"


def uncertainty(attribute: str, explanation: str, preferred: Preference) -> str:
    """The sentence a reader sees: what is uncertain, and on what basis anything is preferred."""
    if preferred == "neither":
        return (
            f"The sources disagree on {attribute}; the evidence does not justify preferring "
            "either value, so both are reported."
        )
    side = "first" if preferred == "a" else "second"
    basis = {
        "different_time_periods": "it is more recent",
        "source_reliability": "its source is markedly more reliable",
    }.get(explanation, "of the stated reason")
    return (
        f"The sources disagree on {attribute}; the {side} value is preferred because {basis}, "
        "but the other is reported for transparency."
    )


# ------------------------------------------------------------------ offline implementation
def _metadata(line: str) -> tuple[datetime | None, float | None]:
    # The last two fields are written by code; a source title (first field) may contain anything,
    # so parse from the right. Preferences are re-checked against real metadata by justified().
    published = reliability = None
    for field in line.rsplit(";", 2)[-2:]:
        key, _, value = field.strip().partition(": ")
        if key == "published" and value != "unknown":
            published = datetime.fromisoformat(value)
        if key == "reliability" and value[:1].isdigit():
            reliability = float(value.split()[0])
    return published, reliability


def local_contradiction_judge(call: ProviderCall) -> str:
    """Deterministic judge: candidates are real conflicts; dates, then reliability, explain them."""
    judgements: list[PairJudgement] = []
    for part in call.untrusted:
        lines = part.text.split("\n")
        side_a = next(i for i, line in enumerate(lines) if line.startswith("A: "))
        side_b = next(i for i, line in enumerate(lines) if line.startswith("B: "))
        date_a, rel_a = _metadata(lines[side_a + 1])
        date_b, rel_b = _metadata(lines[side_b + 1])
        shared = sorted(
            content_terms(lines[side_a][3:]) & content_terms(lines[side_b][3:]), key=len
        )[-3:]
        attribute = " ".join(shared) or "the same subject"
        explanation: Explanation = "unresolved"
        preferred: Preference = "neither"
        if date_a and date_b and date_a != date_b:
            explanation, preferred = "different_time_periods", "a" if date_a > date_b else "b"
        elif rel_a is not None and rel_b is not None and abs(rel_a - rel_b) >= RELIABILITY_MARGIN:
            explanation, preferred = "source_reliability", "a" if rel_a > rel_b else "b"
        judgements.append(
            PairJudgement(
                pair=part.label,
                contradiction=True,
                attribute=attribute[:120],
                explanation=explanation,
                rationale="The statements give different values for the same subject.",
                preferred=preferred,
            )
        )
    return ContradictionOutput(judgements=judgements).model_dump_json()


# --------------------------------------------------------------------------- the stage
class ContradictionStage:
    key = "contradictions"
    weight = 1

    async def run(self, ctx: StageContext) -> dict[str, Any]:
        services = ctx.services
        await creator_access(ctx)
        async with services.database.tenant(ctx.scope, read_only=True) as session:
            evidence = await load_job_evidence(session, ctx.job.organization_id, ctx.job.id)
        candidates = candidate_pairs(evidence.findings)
        stored: list[ResearchContradiction] = []
        for start in range(0, len(candidates), BATCH):
            await ctx.check_cancelled()
            batch = candidates[start : start + BATCH]
            outcome = await services.agents.run(
                CONTRADICTION_JUDGE,
                variables={"objective": ctx.job.objective},
                evidence=[pair_block(candidate) for candidate in batch],
                tools={},
                context=AgentContext(
                    organization_id=ctx.job.organization_id,
                    job_id=ctx.job.id,
                    approved_external="data_policy" in ctx.approvals,
                ),
                classification=Classification.INTERNAL,
            )
            if outcome.termination == "killed":
                raise StageFailed(
                    "agent_disabled", "An administrator has stopped the contradiction judge."
                )
            if not isinstance(outcome.output, ContradictionOutput):
                continue
            by_label = {candidate.label: candidate for candidate in batch}
            seen: set[str] = set()
            for judgement in outcome.output.judgements:
                candidate = by_label.get(judgement.pair)
                if candidate is None or not judgement.contradiction or judgement.pair in seen:
                    continue
                seen.add(judgement.pair)
                stored.append(
                    ResearchContradiction(
                        organization_id=ctx.job.organization_id,
                        job_id=ctx.job.id,
                        finding_a_id=candidate.a.id,
                        finding_b_id=candidate.b.id,
                        attribute=clean_line(judgement.attribute, 120) or "the same subject",
                        explanation=judgement.explanation,
                        rationale=clean_line(judgement.rationale, 400) or "-",
                        preferred=justified(candidate, judgement.explanation, judgement.preferred),
                        agent_run_id=outcome.run_id,
                    )
                )
        async with services.database.tenant(ctx.scope) as session:  # idempotent re-runs
            await session.execute(
                delete(ResearchContradiction).where(
                    ResearchContradiction.organization_id == ctx.job.organization_id,
                    ResearchContradiction.job_id == ctx.job.id,
                )
            )
            session.add_all(stored)
        return {"candidates": len(candidates), "contradictions": len(stored)}
