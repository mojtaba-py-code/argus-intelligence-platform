"""Evaluation datasets: research cases with a fixed corpus and known expectations.

A dataset is a YAML file under ``evals/datasets/``. Each case brings its own corpus - uploaded
documents and web pages served by an in-memory network - and the URLs search returns for it, so a
run is reproducible: only the models under evaluation vary. Expectations name what a correct run
must contain (facts, sources, contradictions, unanswered questions) and what it must never
contain (injected phrases, canary secrets, contacts with attacker hosts).
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Phrase = Annotated[str, Field(min_length=2, max_length=300)]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EvalDocument(_Model):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}\.(md|txt|json|csv|html)$")
    text: str = Field(min_length=1, max_length=50_000)
    classification: Literal["public", "internal", "confidential", "restricted"] = "confidential"


class EvalPage(_Model):
    url: str
    title: str = Field(max_length=300)
    body: str = Field(max_length=50_000)
    """An HTML fragment (or, for ``pdf``, plain text paragraphs separated by blank lines)."""
    published: date | None = None
    format: Literal["html", "pdf"] = "html"

    @field_validator("url")
    @classmethod
    def _https(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme != "https" or not parts.hostname or not parts.path:
            msg = "pages are https URLs with a path"
            raise ValueError(msg)
        return value

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @property
    def path(self) -> str:
        return urlsplit(self.url).path


class Expectation(_Model):
    facts: list[Phrase] = Field(default_factory=list)
    """Phrases (case-insensitive) that included findings must contain between them."""
    sources: list[str] = Field(default_factory=list)
    """URLs or document names the report should cite."""
    contradictions: int = Field(0, ge=0)
    """How many disagreements between sources a correct run reports."""
    unanswered: list[str] = Field(default_factory=list)
    """Question ids a correct run marks "Insufficient evidence."."""
    forbidden: list[Phrase] = Field(default_factory=list)
    """Phrases that must never appear in the report or in anything sent to an external model."""
    never_contacted: list[str] = Field(default_factory=list)
    """Hosts that must never be resolved or contacted."""
    never_sent: list[Phrase] = Field(default_factory=list)
    """Phrases (canaries) that may appear in the report for cleared readers but must never be
    sent to an external model provider."""


class EvalCase(_Model):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,48}$")
    description: str = Field(max_length=500)
    tags: list[str] = Field(default_factory=list)
    objective: str = Field(min_length=10, max_length=2000)
    mode: Literal["web", "documents", "hybrid"] = "hybrid"
    documents: list[EvalDocument] = Field(default_factory=list)
    pages: list[EvalPage] = Field(default_factory=list)
    search_results: list[str] = Field(default_factory=list)
    """URLs the search provider returns for every query of this case (in order)."""
    expect: Expectation = Expectation()

    @model_validator(mode="after")
    def _consistent(self) -> EvalCase:
        urls = {page.url for page in self.pages}
        unknown = [url for url in self.search_results if url not in urls]
        if unknown:
            msg = f"case {self.id}: search results without a page: {unknown}"
            raise ValueError(msg)
        return self


class EvalDataset(_Model):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,48}$")
    version: int = Field(ge=1)
    description: str = Field(max_length=1000)
    cases: list[EvalCase] = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def _unique(self) -> EvalDataset:
        ids = [case.id for case in self.cases]
        if len(ids) != len(set(ids)):
            msg = "case ids must be unique"
            raise ValueError(msg)
        return self

    def select(self, tags: set[str] | None) -> list[EvalCase]:
        return [c for c in self.cases if not tags or tags & set(c.tags)]


def load_dataset(path: Path) -> EvalDataset:
    with path.open(encoding="utf-8") as handle:
        return EvalDataset.model_validate(yaml.safe_load(handle))
