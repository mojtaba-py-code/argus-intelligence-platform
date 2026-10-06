"""Phases 13-14 - analysts per sub-question, orchestrated by code.

For each planned sub-question the orchestrator (this stage - not a model) retrieves evidence
inside the job creator's *current* authorised scope, then runs the analyst agent. The analyst
reads untrusted text, so under the taint rule its only tool is ``search_documents`` - a search
of the project's own knowledge, with no network access and no side effects. It cannot browse,
fetch, send or write; a page that tells it to do so is just text. Its findings are verified
mechanically (each quote must appear in a chunk it was given under that id); an unsupported
"fact" is downgraded to a hypothesis with capped confidence.
"""

from __future__ import annotations

import re
from collections import Counter
from decimal import Decimal
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete

from argus.core.classification import Classification
from argus.core.errors import PermissionDenied
from argus.core.ids import uuid7
from argus.modules.agents.catalogue import TOOLS
from argus.modules.agents.runtime import (
    AgentContext,
    AgentOutcome,
    AgentSpec,
    ToolRequest,
    ToolResult,
    ToolSpec,
)
from argus.modules.knowledge.citations import EvidenceRegistry, quote_supported
from argus.modules.knowledge.retrieval import SearchScope, query_terms
from argus.modules.llm.types import ProviderCall
from argus.modules.research.creator import creator_access
from argus.modules.research.models import ResearchCitation, ResearchFinding
from argus.modules.research.pipeline import ApprovalRequired, StageContext, StageFailed
from argus.modules.tenancy.schemas import DataPolicy
from argus.security.text import clean_line

_SENTENCE: Final = re.compile(r"(?<=[.!?])\s+")
_FILLER: Final = frozenset(
    [
        "what",
        "who",
        "which",
        "how",
        "why",
        "when",
        "where",
        "is",
        "are",
        "was",
        "were",
        "the",
        "of",
        "in",
        "on",
        "for",
        "and",
        "to",
        "a",
        "an",
        "do",
        "does",
        "did",
        "current",
        "state",
        "main",
        "recent",
        "exist",
        "exists",
        "open",
        "problems",
        "players",
        "organisations",
    ]
)
_UNSUPPORTED_CONFIDENCE: Final = 0.3


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    statement: str = Field(min_length=5, max_length=1000)
    kind: Literal["fact", "inference", "hypothesis", "opinion"]
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(min_length=1, max_length=5)
    quote: str = Field(min_length=1, max_length=500)


class FindingsOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[Finding] = Field(max_length=10)
    follow_up_queries: list[Annotated[str, Field(min_length=2, max_length=200)]] = Field(
        default_factory=list, max_length=2
    )
    insufficient_evidence: bool


class SearchDocumentsArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=2, max_length=200)


def _follow_ups(output: BaseModel) -> list[ToolRequest]:
    if not isinstance(output, FindingsOutput):
        return []
    return [ToolRequest("search_documents", {"query": query}) for query in output.follow_up_queries]


ANALYST: Final = AgentSpec(
    name="analyst",
    prompt="analysis.findings",
    output_model=FindingsOutput,
    tools=frozenset({"search_documents"}),
    reads_untrusted=True,
    max_iterations=2,
    max_tool_calls=2,
    max_cost_usd=Decimal("0.50"),
    requests=_follow_ups,
)


# ------------------------------------------------------------------ offline implementation
def _terms(text: str) -> set[str]:
    return query_terms(text) - _FILLER


def local_analyst(call: ProviderCall) -> str:
    """Deterministic analyst: the best-matching sentence per evidence block becomes a quoted fact."""
    terms = _terms(str(call.variables.get("question", "")))
    scored: list[tuple[float, str, str]] = []
    for part in call.untrusted:
        body = part.text.split("\n\n", 1)[-1]
        best = max(
            (
                (len(terms & _terms(sentence)) / max(1, len(terms)), sentence.strip())
                for sentence in _SENTENCE.split(body)
                if len(sentence.strip()) >= 12
            ),
            key=lambda item: item[0],  # ties keep document order, not alphabetical order
            default=(0.0, ""),
        )
        if best[0] > 0:
            scored.append((best[0], part.label, best[1][:500]))
    scored.sort(key=lambda item: -item[0])
    findings = [
        Finding(
            statement=sentence[:1000],
            kind="fact",
            confidence=round(min(1.0, 0.5 + 0.5 * score), 2),
            evidence=[label],
            quote=sentence,
        )
        for score, label, sentence in scored[:3]
    ]
    follow_ups: list[str] = []
    if not findings and call.variables.get("may_request_more"):
        follow_ups = [str(call.variables.get("objective", ""))[:200]]
    return FindingsOutput(
        findings=findings, follow_up_queries=follow_ups, insufficient_evidence=not findings
    ).model_dump_json()


# --------------------------------------------------------------------------- the stage
_ORIGINS: Final = {"web": ["web"], "documents": ["document"], "hybrid": ["document", "web"]}


class AnalyzeStage:
    key = "analyze"
    weight = 4

    async def run(self, ctx: StageContext) -> dict[str, Any]:
        services = ctx.services
        scope, policy = await self._scope(ctx)
        await self._require_data_policy_approval(ctx, scope, policy)
        questions = ctx.outputs.get("plan", {}).get("questions", [])
        async with services.database.tenant(ctx.scope) as session:  # idempotent re-runs
            await session.execute(
                delete(ResearchFinding).where(ResearchFinding.job_id == ctx.job.id)
            )
        totals: Counter[str] = Counter()
        for question in questions:
            await ctx.check_cancelled()
            registry = EvidenceRegistry()
            query = " ".join([question["question"], *question.get("search_queries", [])[:2]])
            hits = await services.knowledge.retriever.search(scope, query, policy=policy, limit=8)
            outcome = await services.agents.run(
                ANALYST,
                variables={"objective": ctx.job.objective, "question": question["question"]},
                evidence=registry.add(hits),
                tools={"search_documents": self._search_tool(services, scope, policy, registry)},
                context=AgentContext(
                    organization_id=ctx.job.organization_id,
                    job_id=ctx.job.id,
                    approved_external="data_policy" in ctx.approvals,
                ),
                classification=Classification.INTERNAL,
            )
            if outcome.termination == "killed":
                raise StageFailed(
                    "agent_disabled", "An administrator has stopped the analyst agent."
                )
            totals["evidence"] += len(registry)
            if not isinstance(outcome.output, FindingsOutput):
                totals["unanswered"] += 1
                continue
            stored, verified = await self._store(ctx, question["id"], outcome, registry)
            totals["findings"] += stored
            totals["verified"] += verified
        return {"questions": len(questions), **totals}

    @staticmethod
    def _search_tool(
        services: Any, scope: SearchScope, policy: DataPolicy, registry: EvidenceRegistry
    ) -> ToolSpec:
        async def search_documents(arguments: BaseModel) -> ToolResult:
            if not isinstance(arguments, SearchDocumentsArgs):  # the runtime validated it
                msg = "search_documents received unexpected arguments"
                raise TypeError(msg)
            hits = await services.knowledge.retriever.search(
                scope, arguments.query, policy=policy, limit=4
            )
            parts = registry.add(hits)
            return ToolResult(parts, {"query": arguments.query[:200], "new_evidence": len(parts)})

        declaration = TOOLS["search_documents"]
        return ToolSpec(
            name=declaration.name,
            input_model=SearchDocumentsArgs,
            side_effects=declaration.side_effects,
            handler=search_documents,
            description=declaration.description,
        )

    @staticmethod
    async def _require_data_policy_approval(
        ctx: StageContext, scope: SearchScope, policy: DataPolicy
    ) -> None:
        """Under ``external_above_ceiling = "approval"``, evidence above the external ceiling may
        reach an external model only once a human approved it for this job. Ask before analysing -
        and only if such evidence exists in scope and an external model could serve the task;
        otherwise the gateway keeps the analysis local without interrupting anyone."""
        if policy.external_above_ceiling != "approval" or "data_policy" in ctx.approvals:
            return
        models = ctx.services.gateway.external_models(ANALYST.prompt)
        if not models:
            return
        highest = await ctx.services.knowledge.retriever.highest_classification(scope)
        if highest is None or highest <= policy.external:
            return
        raise ApprovalRequired(
            "data_policy",
            f"Analysis would send {highest.label} evidence to an external model; the "
            f"organisation's policy allows {policy.external.label} without approval.",
            {
                "classification": highest.label,
                "ceiling": policy.external.label,
                "models": models,
                "task": ANALYST.prompt,
            },
        )

    @staticmethod
    async def _scope(ctx: StageContext) -> tuple[SearchScope, DataPolicy]:
        # Re-authorised now, with the creator's current rights (an API key's scopes included):
        # a job never reads more than its creator could read directly at this moment.
        access = await creator_access(ctx)
        try:
            scope = ctx.services.knowledge.scope_for(
                access, origins=_ORIGINS.get(ctx.job.mode, ["document", "web"])
            )
        except PermissionDenied:
            raise StageFailed(
                "access_revoked", "The job's creator can no longer read this project's knowledge."
            ) from None
        return scope, access.org.settings.data_policy

    @staticmethod
    async def _store(
        ctx: StageContext, question_id: str, outcome: AgentOutcome, registry: EvidenceRegistry
    ) -> tuple[int, int]:
        if not isinstance(outcome.output, FindingsOutput):  # checked by the caller
            return 0, 0
        stored = verified_count = 0
        async with ctx.services.database.tenant(ctx.scope) as session:
            for ordinal, finding in enumerate(outcome.output.findings, start=1):
                cited = [
                    (ref, hit)
                    for ref in dict.fromkeys(finding.evidence)
                    if (hit := registry.get(ref)) is not None
                ]
                checks = [
                    (ref, hit, quote_supported(finding.quote, [hit.text])) for ref, hit in cited
                ]
                verified = any(ok for _, _, ok in checks)
                kind = finding.kind
                confidence = finding.confidence
                if not verified:  # unsupported claims are downgraded, never presented as fact
                    kind = "hypothesis" if kind == "fact" else kind
                    confidence = min(confidence, _UNSUPPORTED_CONFIDENCE)
                finding_id = uuid7()
                session.add(
                    ResearchFinding(
                        id=finding_id,
                        organization_id=ctx.job.organization_id,
                        job_id=ctx.job.id,
                        question_id=question_id[:8],
                        ordinal=ordinal,
                        statement=clean_line(finding.statement, 1000) or "-",
                        kind=kind,
                        confidence=confidence,
                        verified=verified,
                        model=outcome.models[-1] if outcome.models else None,
                        agent_run_id=outcome.run_id,
                        evidence_classification=int(registry.max_classification),
                    )
                )
                await session.flush()
                for ref, hit, ok in checks:
                    session.add(
                        ResearchCitation(
                            organization_id=ctx.job.organization_id,
                            finding_id=finding_id,
                            chunk_id=hit.chunk_id,
                            ref=ref[:8],
                            quote=finding.quote[:500],
                            verified=ok,
                        )
                    )
                stored += 1
                verified_count += int(verified)
        return stored, verified_count
