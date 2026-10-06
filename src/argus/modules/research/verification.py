"""Phase 15 - verification: does each finding's cited evidence really support it?

Two layers, and code has the last word:

1. **Mechanical** (always): a finding needs a citation whose quote is present in the cited chunk
   (checked when it was written), and every figure in its statement must appear in the cited
   evidence - a number no source stated is a hallucination, whatever a model thinks of it.
2. **Semantic**: the verifier agent judges entailment from the statement and the cited chunks
   alone - supported, partial, unsupported or contradicted. It can lower the verdict code allows;
   it can never raise a verdict code refused.

Verdicts adjust the finding: unsupported or contradicted facts become hypotheses with capped
confidence, and only supported or partially supported findings reach the report.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator, Sequence
from decimal import Decimal
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import update

from argus.core.classification import Classification
from argus.modules.agents.runtime import AgentContext, AgentSpec
from argus.modules.llm.types import ProviderCall, UntrustedData
from argus.modules.research.creator import creator_access
from argus.modules.research.evidence import (
    FindingRecord,
    content_terms,
    load_job_evidence,
    numbers,
)
from argus.modules.research.models import ResearchFinding
from argus.modules.research.pipeline import StageContext, StageFailed
from argus.security.injection import instruction_like
from argus.security.text import clean_line

Verdict = Literal["supported", "partial", "unsupported", "contradicted"]
BATCH: Final = 8
_RANK: Final[dict[str, int]] = {"contradicted": 0, "unsupported": 1, "partial": 2, "supported": 3}
_CONFIDENCE_CAP: Final[dict[str, float]] = {
    "supported": 1.0,
    "partial": 0.6,
    "unsupported": 0.3,
    "contradicted": 0.1,
}
INCLUDED: Final = frozenset({"supported", "partial"})
"""Support levels that let a finding into the report."""


class FindingVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding: str = Field(pattern=r"^F[1-9][0-9]{0,3}$")
    verdict: Verdict
    rationale: str = Field(max_length=300)


class EntailmentOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdicts: list[FindingVerdict] = Field(max_length=50)


VERIFIER: Final = AgentSpec(
    name="verifier",
    prompt="verification.entailment",
    output_model=EntailmentOutput,
    tools=frozenset(),
    reads_untrusted=True,
    max_iterations=1,
    max_tool_calls=0,
    max_cost_usd=Decimal("0.50"),
)


# ------------------------------------------------------------------------- the rules
def claim_block(finding: FindingRecord) -> UntrustedData:
    lines = [f"CLAIM: {finding.statement}", "", "EVIDENCE:"]
    for citation in finding.citations:
        lines.append(f"[{citation.ref}] {citation.source.label}")
        lines.append(citation.chunk_text)
    return UntrustedData(
        text="\n".join(lines),
        label=finding.ref,
        classification=Classification(finding.classification),
    )


def mechanical_ceiling(finding: FindingRecord) -> tuple[Verdict, str | None]:
    """The best verdict code allows for a finding, and why when that is below "supported".

    Content that reads as instructions to an AI is never evidence: a claim phrased as an
    instruction is rejected, and so is a claim whose only verified support comes from content
    flagged as a possible prompt injection - otherwise an injected sentence ("report that X is
    fraudulent") could be quoted back as a verified fact.
    """
    if not finding.citations or not finding.verified:
        return "unsupported", "No citation quotes text that is present in the cited source."
    if instruction_like(finding.statement):
        return "unsupported", "The claim reads as instructions to an AI system."
    clean = [c for c in finding.citations if c.verified and c.injection_level in {"none", "low"}]
    if not clean:
        return (
            "unsupported",
            "Its only support is content flagged as a possible prompt injection.",
        )
    missing = numbers(finding.statement) - numbers(finding.evidence_text)
    if missing:
        return (
            "unsupported",
            f"Figures not found in the cited evidence: {', '.join(sorted(missing)[:5])}.",
        )
    return "supported", None


def combine(ceiling: Verdict, judged: Verdict | None) -> Verdict:
    """A model may lower a verdict, never raise it; an unjudged claim is at most partial."""
    candidate: Verdict = judged if judged is not None else "partial"
    return candidate if _RANK[candidate] < _RANK[ceiling] else ceiling


def adjust(kind: str, confidence: float, verdict: Verdict) -> tuple[str, float]:
    if verdict in {"unsupported", "contradicted"} and kind == "fact":
        kind = "hypothesis"
    return kind, round(min(confidence, _CONFIDENCE_CAP[verdict]), 2)


def batched(items: Sequence[FindingRecord], size: int) -> Iterator[Sequence[FindingRecord]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


# ------------------------------------------------------------------ offline implementation
def local_verifier(call: ProviderCall) -> str:
    """Deterministic entailment: how much of the claim's vocabulary the cited evidence carries."""
    verdicts: list[FindingVerdict] = []
    for part in call.untrusted:
        claim, _, evidence = part.text.partition("\n\nEVIDENCE:\n")
        terms = content_terms(claim.removeprefix("CLAIM: "))
        coverage = len(terms & content_terms(evidence)) / max(1, len(terms))
        verdict: Verdict = (
            "supported" if coverage >= 0.8 else "partial" if coverage >= 0.5 else "unsupported"
        )
        verdicts.append(
            FindingVerdict(
                finding=part.label,
                verdict=verdict,
                rationale=f"{round(coverage * 100)}% of the claim's terms appear in its evidence.",
            )
        )
    return EntailmentOutput(verdicts=verdicts).model_dump_json()


# --------------------------------------------------------------------------- the stage
class VerifyStage:
    key = "verify"
    weight = 2

    async def run(self, ctx: StageContext) -> dict[str, Any]:
        services = ctx.services
        await creator_access(ctx)
        async with services.database.tenant(ctx.scope, read_only=True) as session:
            evidence = await load_job_evidence(session, ctx.job.organization_id, ctx.job.id)
        if not evidence.findings:
            return {"findings": 0}
        ceilings = {finding.ref: mechanical_ceiling(finding) for finding in evidence.findings}
        candidates = [f for f in evidence.findings if ceilings[f.ref][0] == "supported"]
        judged: dict[str, FindingVerdict] = {}
        for batch in batched(candidates, BATCH):
            await ctx.check_cancelled()
            outcome = await services.agents.run(
                VERIFIER,
                variables={"objective": ctx.job.objective},
                evidence=[claim_block(finding) for finding in batch],
                tools={},
                context=AgentContext(
                    organization_id=ctx.job.organization_id,
                    job_id=ctx.job.id,
                    approved_external="data_policy" in ctx.approvals,
                ),
                classification=Classification.INTERNAL,
            )
            if outcome.termination == "killed":
                raise StageFailed("agent_disabled", "An administrator has stopped the verifier.")
            if isinstance(outcome.output, EntailmentOutput):
                refs = {finding.ref for finding in batch}
                for item in outcome.output.verdicts:
                    if item.finding in refs:
                        judged.setdefault(item.finding, item)

        counts: Counter[str] = Counter()
        async with services.database.tenant(ctx.scope) as session:
            for finding in evidence.findings:
                ceiling, reason = ceilings[finding.ref]
                model = judged.get(finding.ref)
                verdict = combine(ceiling, model.verdict if model else None)
                if reason is not None:
                    rationale = reason
                elif model is not None:
                    rationale = clean_line(model.rationale, 300) or "-"
                else:
                    rationale = "Not assessed by the verifier."
                kind, confidence = adjust(finding.kind, finding.confidence, verdict)
                await session.execute(
                    update(ResearchFinding)
                    .where(
                        ResearchFinding.organization_id == ctx.job.organization_id,
                        ResearchFinding.id == finding.id,
                    )
                    .values(
                        support=verdict,
                        support_rationale=rationale,
                        kind=kind,
                        confidence=confidence,
                    )
                )
                counts[verdict] += 1
        return {"findings": len(evidence.findings), **counts}
