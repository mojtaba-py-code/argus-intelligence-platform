"""Monitor API models."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import Field, model_validator

from argus.core.schemas import Name, RequestModel, ResponseModel, StrictBool, StrictFloat, StrictInt
from argus.modules.monitoring.assess import Topic
from argus.modules.monitoring.models import MAX_INTERVAL_MINUTES, MIN_INTERVAL_MINUTES

Url = Annotated[str, Field(min_length=10, max_length=2000)]
Query = Annotated[str, Field(min_length=2, max_length=200)]


class CreateMonitorRequest(RequestModel):
    name: Name
    kind: Literal["urls", "search"]
    urls: list[Url] = Field(default_factory=list, max_length=100)
    queries: list[Query] = Field(default_factory=list, max_length=20)
    topics: list[Topic] = Field(default_factory=list, max_length=8)
    interval_minutes: StrictInt = Field(1440, ge=MIN_INTERVAL_MINUTES, le=MAX_INTERVAL_MINUTES)
    significance_threshold: StrictFloat = Field(0.5, ge=0, le=1)
    notify_email: StrictBool = False

    @model_validator(mode="after")
    def _targets(self) -> CreateMonitorRequest:
        if self.kind == "urls" and (not self.urls or self.queries):
            msg = "a 'urls' monitor needs urls and no queries"
            raise ValueError(msg)
        if self.kind == "search" and (not self.queries or self.urls):
            msg = "a 'search' monitor needs queries and no urls"
            raise ValueError(msg)
        return self


class UpdateMonitorRequest(RequestModel):
    name: Name | None = None
    topics: list[Topic] | None = Field(None, max_length=8)
    interval_minutes: StrictInt | None = Field(
        None, ge=MIN_INTERVAL_MINUTES, le=MAX_INTERVAL_MINUTES
    )
    significance_threshold: StrictFloat | None = Field(None, ge=0, le=1)
    notify_email: StrictBool | None = None
    status: Literal["active", "paused"] | None = None


class MonitorTargetResponse(ResponseModel):
    id: UUID
    url: str
    discovered: bool
    last_checked_at: datetime | None
    last_status: str | None
    last_error_code: str | None


class MonitorResponse(ResponseModel):
    id: UUID
    project_id: UUID
    name: str
    kind: str
    queries: list[str]
    topics: list[str]
    interval_minutes: int
    significance_threshold: float
    notify_email: bool
    status: str
    next_run_at: datetime
    last_run_at: datetime | None
    last_error_code: str | None
    created_at: datetime
    targets: list[MonitorTargetResponse] = Field(default_factory=list)


class MonitorChangeResponse(ResponseModel):
    id: UUID
    monitor_id: UUID
    target_id: UUID
    url: str
    topics: list[str]
    significance: float
    summary: str
    diff: dict[str, Any]
    alerted: bool
    status: str
    created_at: datetime


class ChangeDecisionRequest(RequestModel):
    status: Literal["acknowledged", "dismissed"]
