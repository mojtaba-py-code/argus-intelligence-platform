"""Cited answers over a project's knowledge (the generation half of RAG).

retrieve (authorised scope) → pack evidence → ``knowledge.answer`` through the gateway →
**verify every citation mechanically**: a claim counts only if it cites evidence that was actually
supplied and its quote appears, after whitespace/case normalisation, in a cited chunk. Claims that
fail are returned flagged, never presented as supported; if nothing survives, the answer is
"insufficient evidence". The model is never trusted to have cited correctly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Annotated, Final, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from argus.core.classification import Classification
from argus.core.errors import RateLimited, ServiceUnavailable
from argus.core.schemas import RequestModel, ResponseModel, StrictInt, clean_text
from argus.modules.knowledge.citations import quote_supported
from argus.modules.knowledge.context import EvidenceItem, pack_evidence
from argus.modules.knowledge.retrieval import query_terms
from argus.modules.knowledge.service import KnowledgeService
from argus.modules.llm.deployments import PromptService
from argus.modules.llm.gateway import LLMGateway
from argus.modules.llm.types import (
    CallContext,
    LLMRequest,
    LLMUnavailable,
    ProviderCall,
    UntrustedData,
)
from argus.modules.tenancy.authorization import ProjectAccess
from argus.security.permissions import Permission
from argus.security.ratelimit import POLICIES, RateLimiter

INSUFFICIENT: Final = "Insufficient evidence: the available sources do not answer this question."
_SENTENCE: Final = re.compile(r"(?<=[.!?])\s+")
_EVIDENCE_TOKENS: Final = 12_000


# ------------------------------------------------------------------- model output schema
class AnswerClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    statement: str = Field(min_length=1, max_length=1000)
    evidence: list[str] = Field(min_length=1, max_length=5)
    quote: str = Field(min_length=1, max_length=500)


class AnswerOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer: str = Field(max_length=4000)
    claims: list[AnswerClaim] = Field(max_length=20)
    insufficient_evidence: bool


# ------------------------------------------------------------------------ API models
def _question(value: str) -> str:
    value = " ".join(clean_text(value).split())
    if len(value) < 3:
        msg = "the question must contain at least 3 characters"
        raise ValueError(msg)
    return value


class AskRequest(RequestModel):
    question: Annotated[str, Field(max_length=1000), AfterValidator(_question)]
    max_evidence: StrictInt = Field(6, ge=1, le=12)
    origins: list[Literal["document", "web"]] | None = Field(None, min_length=1, max_length=2)


class CitationResponse(ResponseModel):
    ref: str
    chunk_id: UUID
    title: str | None
    url: str | None
    filename: str | None
    page_start: int | None
    page_end: int | None


class ClaimResponse(ResponseModel):
    statement: str
    quote: str
    citations: list[CitationResponse]
    verified: bool


class AskResponse(ResponseModel):
    question: str
    answer: str
    insufficient_evidence: bool
    claims: list[ClaimResponse]
    evidence_count: int
    provider: str | None
    model: str | None
    cost_usd: Decimal


# ------------------------------------------------------------------------ verification
def verify(output: AnswerOutput, items: dict[str, EvidenceItem]) -> list[ClaimResponse]:
    claims: list[ClaimResponse] = []
    for claim in output.claims:
        cited = [items[ref] for ref in dict.fromkeys(claim.evidence) if ref in items]
        verified = bool(cited) and quote_supported(claim.quote, [item.hit.text for item in cited])
        claims.append(
            ClaimResponse(
                statement=claim.statement,
                quote=claim.quote,
                citations=[_citation(item) for item in cited],
                verified=verified,
            )
        )
    return claims


def _citation(item: EvidenceItem) -> CitationResponse:
    hit = item.hit
    return CitationResponse(
        ref=item.ref,
        chunk_id=hit.chunk_id,
        title=hit.title,
        url=hit.url,
        filename=hit.filename,
        page_start=hit.page_start,
        page_end=hit.page_end,
    )


def evidence_text(item: EvidenceItem) -> str:
    return f"source: {item.label}\ntitle: {item.hit.title or '-'}\n\n{item.hit.text}"


# ---------------------------------------------------------------- local implementation
def extractive_answer(call: ProviderCall) -> str:
    """Offline ``knowledge.answer``: the best-matching sentence of each evidence block, quoted."""
    terms = query_terms(str(call.variables.get("question", "")))
    scored: list[tuple[float, str, str]] = []
    for part in call.untrusted:
        body = part.text.split("\n\n", 1)[-1]
        best = max(
            (
                (len(terms & query_terms(sentence)) / max(1, len(terms)), sentence.strip())
                for sentence in _SENTENCE.split(body)
                if len(sentence.strip()) >= 8
            ),
            default=(0.0, ""),
        )
        if best[0] > 0:
            scored.append((best[0], part.label, best[1][:500]))
    scored.sort(key=lambda item: -item[0])
    claims = [
        AnswerClaim(statement=sentence, evidence=[label], quote=sentence)
        for _, label, sentence in scored[:3]
    ]
    if not claims:
        return AnswerOutput(
            answer=INSUFFICIENT, claims=[], insufficient_evidence=True
        ).model_dump_json()
    answer = " ".join(f"{claim.statement} [{claim.evidence[0]}]" for claim in claims)
    return AnswerOutput(
        answer=answer[:4000], claims=claims, insufficient_evidence=False
    ).model_dump_json()


# ------------------------------------------------------------------------- the service
@dataclass(frozen=True)
class AnswerDependencies:
    knowledge: KnowledgeService
    gateway: LLMGateway
    prompts: PromptService
    limiter: RateLimiter


class AnswerService:
    def __init__(self, deps: AnswerDependencies) -> None:
        self._d = deps

    async def ask(self, access: ProjectAccess, request: AskRequest) -> AskResponse:
        access.require(Permission.RESEARCH_CREATE)  # asking spends the organisation's budget
        principal = access.org.principal
        decision = await self._d.limiter.hit(
            POLICIES["knowledge.ask.user"], str(principal.user_id or principal.api_key_id)
        )
        if not decision.allowed:
            raise RateLimited(decision.retry_after_s)
        scope = self._d.knowledge.scope_for(access, origins=list(request.origins or []))
        hits = await self._d.knowledge.retriever.search(
            scope,
            request.question,
            policy=access.org.settings.data_policy,
            limit=request.max_evidence,
        )
        if not hits:
            return self._insufficient(request, evidence=0)
        pack = pack_evidence(hits, budget_tokens=_EVIDENCE_TOKENS)
        items = {item.ref: item for item in pack.items}
        prompt = await self._d.prompts.render("knowledge.answer", {"question": request.question})
        try:
            result = await self._d.gateway.generate(
                LLMRequest(
                    prompt=prompt,
                    untrusted=tuple(
                        UntrustedData(
                            evidence_text(item), item.ref, Classification(item.hit.classification)
                        )
                        for item in pack.items
                    ),
                    classification=Classification.INTERNAL,
                ),
                CallContext(organization_id=access.org.organization_id),
            )
        except LLMUnavailable as exc:
            raise ServiceUnavailable(
                "No model is currently available for this request. Try again later."
            ) from exc
        output = result.parsed if isinstance(result.parsed, AnswerOutput) else None
        claims = verify(output, items) if output is not None else []
        supported = [claim for claim in claims if claim.verified]
        insufficient = output is None or output.insufficient_evidence or not supported
        return AskResponse(
            question=request.question,
            answer=INSUFFICIENT if insufficient or output is None else output.answer,
            insufficient_evidence=insufficient,
            claims=claims,
            evidence_count=len(pack.items),
            provider=result.provider,
            model=result.served_model,
            cost_usd=result.cost_usd,
        )

    @staticmethod
    def _insufficient(request: AskRequest, *, evidence: int) -> AskResponse:
        return AskResponse(
            question=request.question,
            answer=INSUFFICIENT,
            insufficient_evidence=True,
            claims=[],
            evidence_count=evidence,
            provider=None,
            model=None,
            cost_usd=Decimal(0),
        )
