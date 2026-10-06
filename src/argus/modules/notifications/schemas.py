"""Notification API models."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from argus.core.schemas import ResponseModel


class NotificationResponse(ResponseModel):
    id: UUID
    event: str
    title: str
    body: str
    link: str | None
    read_at: datetime | None
    created_at: datetime


class UnreadCountResponse(ResponseModel):
    unread: int
