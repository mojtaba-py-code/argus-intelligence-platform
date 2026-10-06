"""Document API models."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from pydantic import BeforeValidator

from argus.core.classification import Classification
from argus.core.schemas import ResponseModel


def _hex(value: object) -> object:
    return value.hex() if isinstance(value, bytes) else value


def _label(value: object) -> object:
    return Classification(value).label if isinstance(value, int) else value


class DocumentResponse(ResponseModel):
    id: UUID
    project_id: UUID
    filename: str
    kind: str
    media_type: str
    byte_size: int
    sha256: Annotated[str, BeforeValidator(_hex)]
    classification: Annotated[str, BeforeValidator(_label)]
    status: str
    error_code: str | None
    scan_engine: str | None
    scanned_at: datetime | None
    title: str | None
    author: str | None
    language: str | None
    page_count: int | None
    text_chars: int
    injection_level: str
    injection_score: float
    created_at: datetime
    processed_at: datetime | None


class DocumentDetail(DocumentResponse):
    scan_signature: str | None
    text_excerpt: str | None = None
    injection_signals: list[dict[str, Any]]
    details: dict[str, Any]


class DownloadLinkResponse(ResponseModel):
    url: str
    expires_at: datetime
