"""Phase 15 - the report: prose from a model, structure, checks and assembly by code.

* The **reporter** agent writes the executive summary, a narrative per answered question,
  recommendations and limitations - from verified findings only, referenced as ``F1``, ``F2``...
* **Code checks the prose**: references must point at included findings; any sentence that
  states a figure absent from the evidence is removed; recommendations without supporting
  findings are dropped. Code fills what is missing deterministically and decides which questions
  are answered - a question without supported findings says "Insufficient evidence.".
* The **critic** agent reviews the draft against a rubric (coverage, support, balance, clarity).
  Its scores are advisory; together with the mechanical checks they can trigger one revision
  while the budget allows.
* Everything a source wrote is untrusted: URLs inside it are defanged (``hxxps://``) so no
  renderer turns them into links or images; only collected sources are linked, in the appendix.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal
from statistics import fmean
from typing import Annotated, Any, Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from argus.core.classification import Classification
from argus.modules.agents.models import AgentRun
from argus.modules.agents.runtime import AgentContext, AgentSpec
from argus.modules.llm.types import ProviderCall, UntrustedData
from argus.modules.research.contradictions import uncertainty
from argus.modules.research.creator import creator_access
from argus.modules.research.evidence import FindingRecord, JobEvidence, load_job_evidence, numbers
from argus.modules.research.exports import render_markdown
from argus.modules.research.models import (
    ApprovalRequest,
    ResearchContradiction,
    ResearchJob,
    ResearchReport,
)
from argus.modules.research.pipeline import StageContext, StageFailed
from argus.modules.research.report_model import (
    INSUFFICIENT_EVIDENCE,
    ORIGINS,
    PREFERENCES,
    SCHEMA_VERSION,
    ReportCitation,
    ReportContradiction,
    ReportDocument,
    ReportFinding,
    ReportMethodology,
    ReportQuality,
    ReportRecommendation,
    ReportSection,
    ReportSource,
    SectionStatus,
)
from argus.modules.research.verification import INCLUDED
from argus.security.injection import instruction_like
from argus.security.text import sanitize_text

REPORT_VERSION: Final = 1
MAX_RECOMMENDATIONS: Final = 10
_SENTENCE: Final = re.compile(r"(?<=[.!?])\s+")
_REF: Final = re.compile(r"\bF[1-9][0-9]{0,3}\b")
_SCHEME: Final = re.compile(r"(?i)\b(https?|ftp)://")
_WWW: Final = re.compile(r"(?i)\bwww\.")
_DEFANGED: Final = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}


def defang(text: str) -> str:
    """Neutralise URLs in untrusted text: readable, but no renderer will link or fetch them."""
    text = _SCHEME.sub(lambda m: f"{_DEFANGED[m.group(1).lower()]}://", text)
    return _WWW.sub("www[.]", text)


def prose(text: str, limit: int) -> str:
    return defang(" ".join(sanitize_text(text).text.split()))[:limit]


# -------------------------------------------------------------------------- model I/O
class DraftSection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question_id: str = Field(pattern=r"^q[1-9][0-9]?$")
    narrative: str = Field(max_length=2500)


class DraftRecommendation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=5, max_length=500)
    findings: list[Annotated[str, Field(pattern=r"^F[1-9][0-9]{0,3}$")]] = Field(
        min_length=1, max_length=5
    )


class ReportDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")

    executive_summary: str = Field(max_length=4000)
    sections: list[DraftSection] = Field(max_length=8)
    recommendations: list[DraftRecommendation] = Field(default_factory=list, max_length=8)
    limitations: list[Annotated[str, Field(max_length=300)]] = Field(
        default_factory=list, max_length=6
    )


class CriticScores(BaseModel):
    model_config = ConfigDict(extra="forbid")

    coverage: float = Field(ge=0, le=1)
    support: float = Field(ge=0, le=1)
    balance: float = Field(ge=0, le=1)
    clarity: float = Field(ge=0, le=1)


class CriticOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scores: CriticScores
    issues: list[Annotated[str, Field(max_length=300)]] = Field(default_factory=list, max_length=8)


REPORTER: Final = AgentSpec(
    name="reporter",
    prompt="report.compose",
    output_model=ReportDraft,
    tools=frozenset(),
    reads_untrusted=True,
    max_iterations=1,
    max_tool_calls=0,
    max_cost_usd=Decimal("1.00"),
)
CRITIC: Final = AgentSpec(
    name="critic",
    prompt="report.critic",
    output_model=CriticOutput,
    tools=frozenset(),
    reads_untrusted=True,
    max_iterations=1,
    max_tool_calls=0,
    max_cost_usd=Decimal("0.50"),
)


# ------------------------------------------------------------------------ the inputs
@dataclass(frozen=True)
class ReportInputs:
    questions: list[dict[str, Any]]
    evidence: JobEvidence
    included: dict[str, FindingRecord]
    by_question: dict[str, list[FindingRecord]]
    contradictions: list[tuple[str, str, ResearchContradiction]]
    merged: int = 0
    """Included findings that repeated an earlier one (same claim, kind and sources)."""

    @property
    def rejected(self) -> int:
        return sum(1 for f in self.evidence.findings if f.support not in INCLUDED)

    @property
    def answered(self) -> list[str]:
        return [q["id"] for q in self.questions if self.by_question.get(q["id"])]

    @property
    def allowed_numbers(self) -> set[str]:
        """Figures the prose may state: those in the included evidence, plus counts no larger
        than the report's own structure ("2 of 3 questions", "1 contradiction")."""
        largest = max(
            len(self.questions),
            len(self.included),
            len(self.contradictions),
            len(self.evidence.sources),
        )
        allowed: set[str] = {str(count) for count in range(largest + 1)}
        for finding in self.included.values():
            allowed |= numbers(finding.statement)
            for citation in finding.citations:
                allowed |= numbers(citation.quote)
        for question in self.questions:
            allowed |= numbers(str(question.get("question", "")))
        return allowed

    @property
    def classification(self) -> Classification:
        return Classification(max((f.classification for f in self.included.values()), default=0))


def build_inputs(
    questions: list[dict[str, Any]],
    evidence: JobEvidence,
    contradictions: list[ResearchContradiction],
) -> ReportInputs:
    """The verified findings the report may use, by question.

    One claim found for several questions (same wording, kind and sources - the analysts work
    per question) is one finding: the first keeps its reference and is listed under every
    question it answers, instead of the report repeating it as F1, F4, F7...
    """
    included: dict[str, FindingRecord] = {}
    by_question: dict[str, list[FindingRecord]] = defaultdict(list)
    first: dict[tuple[str, str, frozenset[str]], FindingRecord] = {}
    refs: dict[UUID, str] = {}
    for finding in evidence.findings:
        if finding.support not in INCLUDED:
            continue
        key = (
            " ".join(finding.statement.casefold().split()),
            finding.kind,
            frozenset(c.source.key for c in finding.citations),
        )
        canonical = first.setdefault(key, finding)
        refs[finding.id] = canonical.ref
        if canonical is finding:
            included[finding.ref] = finding
        listed = by_question[finding.question_id]
        if all(f.id != canonical.id for f in listed):
            listed.append(canonical)
    pairs = [
        (refs[c.finding_a_id], refs[c.finding_b_id], c)
        for c in contradictions
        if c.finding_a_id in refs
        and c.finding_b_id in refs
        and refs[c.finding_a_id] != refs[c.finding_b_id]
    ]
    return ReportInputs(
        questions, evidence, included, dict(by_question), pairs, merged=len(refs) - len(included)
    )


def question_blocks(inputs: ReportInputs) -> list[UntrustedData]:
    blocks: list[UntrustedData] = []
    for index, question in enumerate(inputs.questions, start=1):
        findings = inputs.by_question.get(question["id"], [])
        lines = [
            f"QUESTION {question['id']}: {question.get('question', '')}",
            f"STATUS: {'answered' if findings else 'insufficient evidence'}",
            "FINDINGS:" if findings else "FINDINGS: none",
        ]
        lines += [
            f"{f.ref} [{f.kind}; confidence {f.confidence:.2f}; {f.support}]: {f.statement} "
            f"(sources: {', '.join(sorted({c.source.key for c in f.citations}))})"
            for f in findings
        ]
        blocks.append(
            UntrustedData(
                text="\n".join(lines),
                label=f"Q{index}",
                classification=Classification(max((f.classification for f in findings), default=0)),
            )
        )
    if inputs.contradictions:
        blocks.append(
            UntrustedData(
                text="\n".join(
                    f"C{i}: {a} vs {b} on {c.attribute} - {c.explanation}; preferred: {c.preferred}"
                    for i, (a, b, c) in enumerate(inputs.contradictions, start=1)
                ),
                label="C",
                classification=inputs.classification,
            )
        )
    return blocks


def render_draft(draft: ReportDraft) -> str:
    """The draft as plain text, for the critic."""
    parts = ["EXECUTIVE SUMMARY", draft.executive_summary, ""]
    for section in draft.sections:
        parts += [f"SECTION {section.question_id}", section.narrative, ""]
    parts.append("RECOMMENDATIONS")
    parts += [f"- {r.text} ({', '.join(r.findings)})" for r in draft.recommendations]
    parts.append("LIMITATIONS")
    parts += [f"- {item}" for item in draft.limitations]
    return "\n".join(parts)


# ------------------------------------------------------------------------ the checks
@dataclass
class Checked:
    summary: str
    narratives: dict[str, str]
    recommendations: list[ReportRecommendation]
    limitations: list[str]
    references: float
    grounding: float
    balance: float
    issues: list[str]

    @property
    def score(self) -> float:
        return round(fmean([self.references, self.grounding, self.balance]), 3)


def _drop_refs(sentence: str, refs: set[str]) -> str:
    for ref in refs:
        sentence = re.sub(rf"\b{ref}\b", "", sentence)
    sentence = re.sub(r"\(\s*[,;\s]*\)", "", sentence)  # "()" left behind
    sentence = re.sub(r"\(\s*[,;]\s*", "(", sentence)
    sentence = re.sub(r"\s*[,;]\s*\)", ")", sentence)
    return " ".join(sentence.replace(" .", ".").split())


def check_draft(draft: ReportDraft, inputs: ReportInputs) -> Checked:
    """Mechanical checks on model prose. Code only removes - it never adds a claim:

    * a sentence stating a figure absent from the evidence is dropped;
    * a sentence whose only references point at findings outside the report (rejected by
      verification, or invented) is dropped - it would repeat an unsupported claim;
    * other references to findings outside the report are removed from the sentence.
    """
    allowed = inputs.allowed_numbers
    valid = set(inputs.included)
    totals = {
        "refs": 0,
        "valid_refs": 0,
        "sentences": 0,
        "dropped": 0,
        "unsupported": 0,
        "instructions": 0,
    }
    mentioned: set[str] = set()

    def clean(text: str, limit: int) -> str:
        kept: list[str] = []
        for sentence in _SENTENCE.split(prose(text, limit)):
            if not sentence:
                continue
            totals["sentences"] += 1
            if numbers(sentence) - allowed:
                totals["dropped"] += 1
                continue
            if instruction_like(sentence):
                totals["instructions"] += 1
                continue
            refs = _REF.findall(sentence)
            totals["refs"] += len(refs)
            good = [ref for ref in refs if ref in valid]
            totals["valid_refs"] += len(good)
            if refs and not good:
                totals["unsupported"] += 1
                continue
            mentioned.update(good)
            kept.append(_drop_refs(sentence, set(refs) - valid))
        return " ".join(kept)

    issues: list[str] = []
    summary = clean(draft.executive_summary, 4000)
    answered = set(inputs.answered)
    narratives = {
        s.question_id: clean(s.narrative, 2500) for s in draft.sections if s.question_id in answered
    }
    recommendations: list[ReportRecommendation] = []
    for item in draft.recommendations:
        text = clean(item.text, 500)
        refs = [ref for ref in dict.fromkeys(item.findings) if ref in valid]
        mentioned.update(refs)
        if text and refs:
            recommendations.append(ReportRecommendation(text=text, findings=refs, basis="evidence"))
        else:
            issues.append("A recommendation without supporting findings was dropped.")
    limitations = [line for line in (clean(item, 300) for item in draft.limitations) if line]

    missing = sorted(answered - {q for q, text in narratives.items() if text})
    if missing:
        issues.append(f"No usable narrative for answered question(s): {', '.join(missing)}.")
    if totals["dropped"]:
        issues.append(
            f"{totals['dropped']} sentence(s) stating figures not found in the evidence were "
            "removed."
        )
    if totals["instructions"]:
        issues.append(
            f"{totals['instructions']} sentence(s) reading as instructions to an AI were removed."
        )
    if totals["unsupported"]:
        issues.append(
            f"{totals['unsupported']} sentence(s) resting only on findings that are not in the "
            "report were removed."
        )
    invalid = totals["refs"] - totals["valid_refs"]
    if invalid:
        issues.append(
            f"{invalid} reference(s) to findings that are not in the report were removed."
        )
    pairs = inputs.contradictions
    balanced = sum(1 for a, b, _ in pairs if a in mentioned and b in mentioned)
    if pairs and balanced < len(pairs):
        issues.append("Not every contradiction is discussed with both of its sides.")
    if answered and not totals["refs"]:
        references = 0.0
    else:
        references = totals["valid_refs"] / totals["refs"] if totals["refs"] else 1.0
    return Checked(
        summary=summary,
        narratives=narratives,
        recommendations=recommendations,
        limitations=limitations,
        references=round(references, 3),
        grounding=round(
            1
            - (totals["dropped"] + totals["unsupported"] + totals["instructions"])
            / totals["sentences"],
            3,
        )
        if totals["sentences"]
        else 1.0,
        balance=round(balanced / len(pairs), 3) if pairs else 1.0,
        issues=issues,
    )


# ------------------------------------------------------------------ offline implementation
def _parse_questions(call: ProviderCall) -> tuple[list[dict[str, Any]], list[str]]:
    sections: list[dict[str, Any]] = []
    contradictions: list[str] = []
    for part in call.untrusted:
        lines = part.text.split("\n")
        if part.label == "C":
            contradictions = lines
            continue
        if not lines or not lines[0].startswith("QUESTION "):
            continue
        qid = lines[0].split(":", 1)[0].removeprefix("QUESTION ").strip()
        findings = [
            (line.split(" ", 1)[0], line.split("]: ", 1)[1].rsplit(" (sources:", 1)[0])
            for line in lines[3:]
            if line.startswith("F") and "]: " in line
        ]
        sections.append({"id": qid, "findings": findings})
    return sections, contradictions


def local_report(call: ProviderCall) -> str:
    """Deterministic composition: the verified findings themselves, referenced."""
    sections, contradictions = _parse_questions(call)
    answered = [s for s in sections if s["findings"]]
    # Each answered question leads with a finding not already in the summary (one finding can
    # answer several questions).
    leads: dict[str, str] = {}
    for section in answered:
        for ref, text in section["findings"]:
            if ref not in leads:
                leads[ref] = text
                break
    summary = [
        (
            f"{len(answered)} of {len(sections)} research questions are answered with verified "
            "evidence."
        ),
        *(f"{text} ({ref})" for ref, text in leads.items()),
    ]
    if contradictions:
        summary.append(f"The sources disagree on {len(contradictions)} point(s).")
    draft_sections = [
        DraftSection(
            question_id=s["id"],
            narrative=" ".join(f"{text} ({ref})" for ref, text in s["findings"])[:2500],
        )
        for s in answered
    ]
    recommendations: list[DraftRecommendation] = []
    for line in contradictions:
        refs = _REF.findall(line.split(" on ", 1)[0])[:2]
        if len(refs) == 2:
            recommendations.append(
                DraftRecommendation(
                    text=f"Check {refs[0]} and {refs[1]} against a primary source.",
                    findings=refs,
                )
            )
    return ReportDraft(
        executive_summary=" ".join(summary)[:4000],
        sections=draft_sections[:8],
        recommendations=recommendations[:8],
        limitations=[],
    ).model_dump_json()


def local_critic(call: ProviderCall) -> str:
    """Deterministic rubric over the draft text (advisory, like the model critic)."""
    draft = next((p.text for p in call.untrusted if p.label == "DRAFT"), "")
    sections, contradictions = _parse_questions(call)
    answered = [s["id"] for s in sections if s["findings"]]
    present = [q for q in answered if f"SECTION {q}\n" in draft]
    sentences = [s for s in _SENTENCE.split(draft.replace("\n", " ")) if s.strip()]
    referenced = [s for s in sentences if _REF.search(s)]
    pairs = [_REF.findall(line.split(" on ", 1)[0])[:2] for line in contradictions]
    balanced = [p for p in pairs if len(p) == 2 and all(ref in draft for ref in p)]
    words = [len(s.split()) for s in sentences] or [0]
    issues: list[str] = []
    if len(present) < len(answered):
        issues.append("Some answered questions have no section.")
    if pairs and len(balanced) < len(pairs):
        issues.append("Some contradictions are not discussed.")
    return CriticOutput(
        scores=CriticScores(
            coverage=round(len(present) / len(answered), 2) if answered else 1.0,
            support=round(len(referenced) / len(sentences), 2) if sentences else 0.0,
            balance=round(len(balanced) / len(pairs), 2) if pairs else 1.0,
            clarity=1.0 if fmean(words) <= 30 else 0.6,
        ),
        issues=issues,
    ).model_dump_json()


# ------------------------------------------------------------------------- assembly
def _fallback_narrative(findings: list[FindingRecord]) -> str:
    return " ".join(f"{prose(f.statement, 1000)} ({f.ref})" for f in findings)


def assemble(
    *,
    job: Any,
    inputs: ReportInputs,
    checked: Checked,
    critic: CriticOutput | None,
    revised: bool,
    methodology: ReportMethodology,
    generated_at: Any,
) -> ReportDocument:
    contested = {ref for a, b, _ in inputs.contradictions for ref in (a, b)}
    sections: list[ReportSection] = []
    for question in inputs.questions:
        findings = inputs.by_question.get(question["id"], [])
        status: SectionStatus
        if findings:
            narrative = checked.narratives.get(question["id"]) or _fallback_narrative(findings)
            status = "answered"
        else:
            narrative, status = INSUFFICIENT_EVIDENCE, "insufficient_evidence"
        sections.append(
            ReportSection(
                question_id=question["id"],
                question=prose(str(question.get("question", "")), 300),
                status=status,
                narrative=narrative,
                findings=[f.ref for f in findings],
            )
        )
    answered = [s for s in sections if s.status == "answered"]
    recommendations = list(checked.recommendations)
    for a, b, c in inputs.contradictions:
        if c.preferred == "neither":
            recommendations.append(
                ReportRecommendation(
                    text=prose(
                        f"Resolve the disagreement on {c.attribute} ({a} vs {b}) with a primary "
                        "source before relying on either value.",
                        500,
                    ),
                    findings=[a, b],
                    basis="contradiction",
                )
            )
    recommendations.extend(
        ReportRecommendation(
            text=f"Collect more evidence on: {section.question}", findings=[], basis="gap"
        )
        for section in sections
        if section.status == "insufficient_evidence"
    )
    rejected = inputs.rejected
    limitations = list(checked.limitations)
    if rejected:
        limitations.append(
            f"{rejected} proposed claim(s) were rejected because their cited evidence did not "
            "support them; they are not part of this report."
        )
    if len(answered) < len(sections):
        limitations.append(
            f"{len(sections) - len(answered)} of {len(sections)} question(s) could not be "
            "answered from the available evidence."
        )
    limitations.append(
        "Only sources collected for this job and the project's documents were considered."
    )
    leads: dict[str, FindingRecord] = {}
    for section in answered:
        lead = next(
            (f for f in inputs.by_question[section.question_id] if f.ref not in leads), None
        )
        if lead is not None and len(leads) < 3:
            leads[lead.ref] = lead
    summary = checked.summary or " ".join(
        [
            (
                f"{len(answered)} of {len(sections)} research questions are answered with "
                "verified evidence."
            )
        ]
        + [f"{prose(f.statement, 500)} ({f.ref})" for f in leads.values()]
    )
    coverage = len(answered) / len(sections) if sections else 0.0
    confidences = [f.confidence for f in inputs.included.values()]
    quality = ReportQuality(
        coverage=round(coverage, 3),
        references=checked.references,
        grounding=checked.grounding,
        balance=checked.balance,
        overall=round(fmean([coverage, checked.references, checked.grounding, checked.balance]), 3),
        critic=critic.scores.model_dump() if critic else None,
        issues=[prose(issue, 300) for issue in checked.issues]
        + ([prose(issue, 300) for issue in critic.issues] if critic else []),
        revised=revised,
    )
    return ReportDocument(
        schema_version=SCHEMA_VERSION,
        job_id=job.id,
        version=REPORT_VERSION,
        title=prose(job.title, 200),
        objective=prose(job.objective, 4000),
        mode=job.mode,
        generated_at=generated_at,
        confidence=round(coverage * fmean(confidences), 3) if confidences else 0.0,
        executive_summary=summary,
        sections=sections,
        findings=[
            ReportFinding(
                ref=f.ref,
                id=f.id,
                question_id=f.question_id,
                statement=prose(f.statement, 1000),
                kind=f.kind,
                confidence=f.confidence,
                support=f.support,
                contested=f.ref in contested,
                citations=[
                    ReportCitation(
                        evidence=c.ref,
                        source=c.source.key,
                        quote=prose(c.quote, 500),
                        verified=c.verified,
                    )
                    for c in f.citations
                ],
            )
            for f in inputs.included.values()
        ],
        contradictions=[
            ReportContradiction(
                a=a,
                b=b,
                attribute=prose(c.attribute, 120),
                explanation=c.explanation,
                rationale=prose(c.rationale, 400),
                preferred=PREFERENCES[c.preferred],
                uncertainty=prose(
                    uncertainty(c.attribute, c.explanation, PREFERENCES[c.preferred]), 400
                ),
            )
            for a, b, c in inputs.contradictions
        ],
        recommendations=recommendations[:MAX_RECOMMENDATIONS],
        limitations=limitations,
        sources=[
            ReportSource(
                key=s.key,
                origin=ORIGINS[s.origin],
                source_id=s.source_id,
                document_id=s.document_id,
                url=s.url,
                title=prose(s.title, 300) if s.title else None,
                filename=prose(s.filename, 255) if s.filename else None,
                source_type=s.source_type,
                media_type=s.media_type,
                retrieved_at=s.retrieved_at,
                published_at=s.published_at,
                content_hash=s.content_hash,
                author=prose(s.author, 200) if s.author else None,
                publisher=prose(s.publisher, 200) if s.publisher else None,
                extraction_method=s.extraction_method,
                reliability=s.reputation,
                trust_tier=s.trust_tier,
            )
            for s in inputs.evidence.sources
            if any(c.source.key == s.key for f in inputs.included.values() for c in f.citations)
        ],
        methodology=methodology,
        quality=quality,
    )


# --------------------------------------------------------------------------- the stage
class ReportStage:
    key = "report"
    weight = 2

    async def run(self, ctx: StageContext) -> dict[str, Any]:
        services = ctx.services
        await creator_access(ctx)
        questions = list(ctx.outputs.get("plan", {}).get("questions", []))
        async with services.database.tenant(ctx.scope, read_only=True) as session:
            evidence = await load_job_evidence(session, ctx.job.organization_id, ctx.job.id)
            contradictions = list(
                (
                    await session.execute(
                        select(ResearchContradiction).where(
                            ResearchContradiction.organization_id == ctx.job.organization_id,
                            ResearchContradiction.job_id == ctx.job.id,
                        )
                    )
                )
                .scalars()
                .all()
            )
        inputs = build_inputs(questions, evidence, contradictions)
        blocks = question_blocks(inputs)
        draft = await self._compose(ctx, blocks, revision=False)
        checked = check_draft(draft, inputs)
        critic = await self._critique(ctx, blocks, draft)
        revised = False
        weak = checked.score < services.settings.reports.revision_threshold or bool(
            critic and min(critic.scores.coverage, critic.scores.support) < 0.6
        )
        if weak and await ctx.remaining_budget() > ctx.job.budget_usd / 4:
            review = UntrustedData(
                text="\n".join(
                    f"- {issue}" for issue in [*checked.issues, *(critic.issues if critic else [])]
                )
                or "- Improve coverage and references.",
                label="REVIEW",
                classification=inputs.classification,
            )
            second = check_draft(await self._compose(ctx, [*blocks, review], revision=True), inputs)
            if second.score >= checked.score:
                checked, revised = second, True
        methodology = await self._methodology(ctx, inputs)
        document = assemble(
            job=ctx.job,
            inputs=inputs,
            checked=checked,
            critic=critic,
            revised=revised,
            methodology=methodology,
            generated_at=services.clock.now(),
        )
        markdown = render_markdown(document)
        values = {
            "organization_id": ctx.job.organization_id,
            "job_id": ctx.job.id,
            "version": REPORT_VERSION,
            "content": document.model_dump(mode="json"),
            "markdown": markdown,
            "quality": document.quality.model_dump(mode="json"),
            "evidence_classification": int(inputs.classification),
        }
        async with services.database.tenant(ctx.scope) as session:
            statement = insert(ResearchReport).values(**values)
            await session.execute(
                statement.on_conflict_do_update(
                    index_elements=["job_id", "version"],
                    set_={
                        "content": statement.excluded.content,
                        "markdown": statement.excluded.markdown,
                        "quality": statement.excluded.quality,
                        "evidence_classification": statement.excluded.evidence_classification,
                        "updated_at": services.clock.now(),
                    },
                )
            )
        return {
            "version": REPORT_VERSION,
            "answered": len(inputs.answered),
            "questions": len(questions),
            "quality": document.quality.overall,
            "revised": revised,
        }

    @staticmethod
    def _context(ctx: StageContext) -> AgentContext:
        return AgentContext(
            organization_id=ctx.job.organization_id,
            job_id=ctx.job.id,
            approved_external="data_policy" in ctx.approvals,
        )

    async def _compose(
        self, ctx: StageContext, blocks: list[UntrustedData], *, revision: bool
    ) -> ReportDraft:
        outcome = await ctx.services.agents.run(
            REPORTER,
            variables={
                "objective": ctx.job.objective,
                "title": ctx.job.title,
                "revision": revision,
            },
            evidence=blocks,
            tools={},
            context=self._context(ctx),
            classification=Classification.INTERNAL,
        )
        if outcome.termination == "killed":
            raise StageFailed("agent_disabled", "An administrator has stopped the report writer.")
        if isinstance(outcome.output, ReportDraft):
            return outcome.output
        return ReportDraft(executive_summary="", sections=[])

    async def _critique(
        self, ctx: StageContext, blocks: list[UntrustedData], draft: ReportDraft
    ) -> CriticOutput | None:
        draft_block = UntrustedData(
            text=render_draft(draft),
            label="DRAFT",
            classification=Classification(max((int(b.classification) for b in blocks), default=0)),
        )
        outcome = await ctx.services.agents.run(
            CRITIC,
            variables={"objective": ctx.job.objective},
            evidence=[*blocks, draft_block],
            tools={},
            context=self._context(ctx),
            classification=Classification.INTERNAL,
        )
        # The critic is advisory: if it is switched off, the report still ships, checked by code.
        return outcome.output if isinstance(outcome.output, CriticOutput) else None

    @staticmethod
    async def _methodology(ctx: StageContext, inputs: ReportInputs) -> ReportMethodology:
        org, job_id = ctx.job.organization_id, ctx.job.id
        async with ctx.services.database.tenant(ctx.scope, read_only=True) as session:
            details = (
                await session.execute(
                    select(AgentRun.details).where(
                        AgentRun.organization_id == org, AgentRun.job_id == job_id
                    )
                )
            ).scalars()
            models: set[str] = set()
            prompts: set[str] = set()
            for item in details:
                models.update(str(m) for m in (item or {}).get("models", []))
                prompts.update(str(p) for p in (item or {}).get("prompts", []))
            approvals = sorted(
                (
                    await session.execute(
                        select(ApprovalRequest.kind).where(
                            ApprovalRequest.organization_id == org,
                            ApprovalRequest.job_id == job_id,
                            ApprovalRequest.status == "approved",
                        )
                    )
                )
                .scalars()
                .all()
            )
            spent = (
                await session.execute(
                    select(ResearchJob.spent_usd).where(
                        ResearchJob.organization_id == org, ResearchJob.id == job_id
                    )
                )
            ).scalar_one()
        return ReportMethodology(
            questions=len(inputs.questions),
            answered=len(inputs.answered),
            sources=len({c.source.key for f in inputs.included.values() for c in f.citations}),
            findings_total=len(inputs.evidence.findings),
            findings_included=len(inputs.included),
            findings_rejected=inputs.rejected,
            contradictions=len(inputs.contradictions),
            models=sorted(models),
            prompts=sorted(prompts),
            approvals=list(dict.fromkeys(approvals)),
            cost_usd=f"{Decimal(spent):.6f}",
        )
