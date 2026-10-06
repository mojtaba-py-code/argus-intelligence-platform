"""Research job API models."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import AfterValidator, Field, field_serializer

from argus.core.schemas import (
    Name,
    RequestModel,
    ResponseModel,
    StrictBool,
    StrictFloat,
    StrictInt,
    clean_text,
)


def _objective(value: str) -> str:
    value = clean_text(value).strip()
    if len(value) < 10:
        msg = "describe the research objective in at least 10 characters"
        raise ValueError(msg)
    return value


Objective = Annotated[str, Field(max_length=4000), AfterValidator(_objective)]


class CreateResearchJobRequest(RequestModel):
    objective: Objective
    title: Name | None = None
    mode: Literal["web", "documents", "hybrid"] = "hybrid"
    budget_usd: StrictFloat | None = Field(None, gt=0, le=1000)
    max_sources: StrictInt | None = Field(None, ge=1, le=500)


class ResearchJobResponse(ResponseModel):
    id: UUID
    project_id: UUID
    title: str
    objective: str
    mode: str
    status: str
    stage: str | None
    progress: int
    budget_usd: Decimal
    spent_usd: Decimal
    input_tokens: int
    output_tokens: int
    max_sources: int
    error_code: str | None
    error_message: str | None
    cancel_requested_at: datetime | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None

    @field_serializer("budget_usd", "spent_usd")
    def _money(self, value: Decimal) -> float:
        return float(value)


class ResearchStepResponse(ResponseModel):
    key: str
    position: int
    status: str
    attempts: int
    output: dict[str, Any]
    error_code: str | None
    started_at: datetime | None
    finished_at: datetime | None


class ApprovalResponse(ResponseModel):
    id: UUID
    job_id: UUID
    project_id: UUID
    kind: str
    status: str
    reason: str
    details: dict[str, Any]
    created_at: datetime
    expires_at: datetime
    decided_at: datetime | None
    decision_note: str | None


class ApprovalDecisionRequest(RequestModel):
    approve: StrictBool
    note: Annotated[str, Field(max_length=500)] | None = None


class ResearchPlanResponse(ResponseModel):
    version: int
    summary: str
    questions: list[dict[str, Any]]
    out_of_scope: list[str]
    model: str | None
    prompt_version: str | None
    created_at: datetime


class CitationView(ResponseModel):
    ref: str
    quote: str
    verified: bool
    chunk_id: UUID
    origin: str
    document_id: UUID | None
    source_id: UUID | None
    title: str | None
    url: str | None
    filename: str | None
    page_start: int | None
    page_end: int | None


class FindingView(ResponseModel):
    id: UUID
    question_id: str
    ordinal: int
    withheld: bool
    """True when the analyst read evidence above the viewer's clearance: the statement and its
    citations are not shown (a model's statement can carry what it read)."""
    statement: str | None
    kind: str
    confidence: float
    verified: bool
    """At least one citation still exists whose quote was found in the cited chunk."""
    support: str
    """Verification verdict: unverified, supported, partial, unsupported or contradicted."""
    support_rationale: str | None
    contested: bool
    """Another source contradicts this finding (see the job's contradictions)."""
    model: str | None
    agent_run_id: UUID | None
    citations: list[CitationView]
    hidden_citations: int
    created_at: datetime


class FindingsResponse(ResponseModel):
    job_id: UUID
    findings: list[FindingView]
    withheld: int


class ToolCallView(ResponseModel):
    id: UUID
    tool: str
    outcome: str
    arguments: dict[str, Any] | None
    result: dict[str, Any] | None
    latency_ms: int
    created_at: datetime


class AgentRunView(ResponseModel):
    id: UUID
    agent: str
    status: str
    iterations: int
    tool_calls: int
    cost_usd: Decimal
    models: list[str]
    prompts: list[str]
    redacted: bool
    """Tool arguments and results are hidden: the run saw evidence above the viewer's clearance."""
    calls: list[ToolCallView]
    created_at: datetime
    finished_at: datetime | None

    @field_serializer("cost_usd")
    def _money(self, value: Decimal) -> float:
        return float(value)


class ContradictionView(ResponseModel):
    id: UUID
    finding_a_id: UUID
    finding_b_id: UUID
    withheld: bool
    """True when either side is withheld from this viewer: the disagreement is not described."""
    attribute: str | None
    explanation: str | None
    rationale: str | None
    preferred: str | None
    created_at: datetime


class ContradictionsResponse(ResponseModel):
    job_id: UUID
    contradictions: list[ContradictionView]
    withheld: int
