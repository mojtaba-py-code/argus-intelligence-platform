"""Knowledge search API models."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AfterValidator, BeforeValidator, Field

from argus.core.classification import Classification
from argus.core.schemas import RequestModel, ResponseModel, StrictInt, clean_text


def _query(value: str) -> str:
    value = " ".join(clean_text(value).split())
    if len(value) < 2:
        msg = "the query must contain at least 2 characters"
        raise ValueError(msg)
    return value


def _label(value: object) -> object:
    return Classification(value).label if isinstance(value, int) else value


class SearchRequest(RequestModel):
    query: Annotated[str, Field(max_length=1000), AfterValidator(_query)]
    limit: StrictInt = Field(8, ge=1, le=25)
    mode: Literal["hybrid", "vector", "keyword"] = "hybrid"
    origins: list[Literal["document", "web"]] | None = Field(None, min_length=1, max_length=2)
    published_after: datetime | None = None


class SearchHit(ResponseModel):
    chunk_id: UUID
    origin: str
    document_id: UUID | None
    source_id: UUID | None
    title: str | None
    url: str | None
    filename: str | None
    page_start: int | None
    page_end: int | None
    text: str
    score: float
    vector_rank: int | None
    keyword_rank: int | None
    injection_level: str
    classification: Annotated[str, BeforeValidator(_label)]
    published_at: datetime | None


class SearchResponse(ResponseModel):
    query: str
    mode: str
    hits: list[SearchHit]
