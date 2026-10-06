"""The canonical report: one JSON schema that Markdown, CSV and PDF are rendered from.

Assembled by code (``reporting.py``); a model contributes only prose that code has checked. The
schema is versioned (``schema_version``) so stored reports stay readable as it evolves.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

SCHEMA_VERSION: Final = "argus.report/1"
INSUFFICIENT_EVIDENCE: Final = "Insufficient evidence."
Preference = Literal["a", "b", "neither"]
Origin = Literal["web", "document"]
SectionStatus = Literal["answered", "insufficient_evidence"]
PREFERENCES: Final[dict[str, Preference]] = {"a": "a", "b": "b", "neither": "neither"}
ORIGINS: Final[dict[str, Origin]] = {"web": "web", "document": "document"}


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ReportSource(_Model):
    key: str
    origin: Origin
    source_id: UUID | None
    document_id: UUID | None
    url: str | None
    title: str | None
    filename: str | None
    source_type: str
    media_type: str | None
    retrieved_at: datetime | None
    published_at: datetime | None
    content_hash: str | None
    author: str | None
    publisher: str | None
    extraction_method: str
    reliability: float | None
    trust_tier: str | None


class ReportCitation(_Model):
    evidence: str
    source: str
    quote: str
    verified: bool


class ReportFinding(_Model):
    ref: str
    id: UUID
    question_id: str
    statement: str
    kind: str
    confidence: float
    support: str
    contested: bool
    citations: list[ReportCitation]


class ReportSection(_Model):
    question_id: str
    question: str
    status: SectionStatus
    narrative: str
    findings: list[str]


class ReportContradiction(_Model):
    a: str
    b: str
    attribute: str
    explanation: str
    rationale: str
    preferred: Preference
    uncertainty: str


class ReportRecommendation(_Model):
    text: str
    findings: list[str]
    basis: Literal["evidence", "gap", "contradiction"]


class ReportQuality(_Model):
    coverage: float
    """Share of the planned questions answered with included findings."""
    references: float
    """Share of finding references in the prose that point at included findings."""
    grounding: float
    """Share of the prose's sentences kept: sentences stating figures absent from the evidence
    are removed."""
    balance: float
    """Share of contradictions whose both sides the prose mentions."""
    overall: float
    critic: dict[str, float] | None
    issues: list[str]
    revised: bool


class ReportMethodology(_Model):
    questions: int
    answered: int
    sources: int
    findings_total: int
    findings_included: int
    findings_rejected: int
    contradictions: int
    models: list[str]
    prompts: list[str]
    approvals: list[str]
    cost_usd: str


class ReportDocument(_Model):
    schema_version: Literal["argus.report/1"]
    job_id: UUID
    version: int
    title: str
    objective: str
    mode: str
    generated_at: datetime
    confidence: float
    executive_summary: str
    sections: list[ReportSection]
    findings: list[ReportFinding]
    contradictions: list[ReportContradiction]
    recommendations: list[ReportRecommendation]
    limitations: list[str]
    sources: list[ReportSource]
    methodology: ReportMethodology
    quality: ReportQuality
