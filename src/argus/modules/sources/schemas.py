"""Source registry API models."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import AfterValidator, Field

from argus.core.schemas import RequestModel, ResponseModel
from argus.security.ssrf import EgressBlocked, normalise_hostname, parse_url


def _url(value: str) -> str:
    try:
        return str(parse_url(value.strip()))
    except EgressBlocked as exc:
        msg = f"this URL cannot be fetched ({exc.reason})"
        raise ValueError(msg) from None


def _domain(value: str) -> str:
    try:
        domain = normalise_hostname(value)
    except EgressBlocked as exc:
        msg = "not a valid domain name"
        raise ValueError(msg) from exc
    if "." not in domain or re.fullmatch(r"[\d.]+", domain):
        msg = "use a registrable domain such as example.com"
        raise ValueError(msg)
    return domain


FetchableURL = Annotated[str, Field(max_length=2048), AfterValidator(_url)]
DomainName = Annotated[str, Field(max_length=253), AfterValidator(_domain)]


class AddSourceRequest(RequestModel):
    url: FetchableURL


class SourceResponse(ResponseModel):
    id: UUID
    project_id: UUID
    url: str
    domain: str
    status: str
    last_error_code: str | None
    title: str | None
    author: str | None
    publisher: str | None
    published_at: datetime | None
    language: str | None
    reputation: float
    trust_tier: str
    injection_level: str
    injection_score: float
    discovered_via: str
    created_at: datetime
    last_fetched_at: datetime | None
    fetch_count: int


class SnapshotSummary(ResponseModel):
    id: UUID
    fetched_at: datetime
    last_seen_at: datetime
    final_url: str
    http_status: int
    media_type: str
    byte_size: int
    title: str | None
    injection_level: str
    injection_score: float


class SnapshotDetail(SnapshotSummary):
    server_ip: str | None
    text_excerpt: str
    injection_signals: list[dict[str, Any]]
    details: dict[str, Any]


class SourceDetail(SourceResponse):
    latest_snapshot: SnapshotDetail | None = None


class DomainPolicyRequest(RequestModel):
    policy: Literal["allow", "block", "require_approval"]
    reputation_override: Annotated[float, Field(ge=0, le=1)] | None = None
    note: Annotated[str, Field(max_length=500)] | None = None


class DomainPolicyResponse(ResponseModel):
    domain: str
    policy: str
    reputation_override: float | None
    note: str | None
    updated_at: datetime
