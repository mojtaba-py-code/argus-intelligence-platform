"""Keyset (cursor) pagination.

Cursors are opaque to clients but are *untrusted input* when they come back: decoding validates
length, encoding, JSON shape, timestamp range and UUID format, and every failure becomes a 422 -
never a 500 from an overflowing ``datetime`` or a malformed UUID.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from argus.core.errors import ValidationFailed

MAX_CURSOR_CHARS = 256
_MIN_YEAR, _MAX_YEAR = 2000, 2200
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100


@dataclass(frozen=True, slots=True)
class Cursor:
    created_at: datetime
    id: UUID


def encode_cursor(created_at: datetime, id_: UUID) -> str:
    payload = json.dumps(
        {"t": created_at.astimezone(UTC).isoformat(), "i": str(id_)}, separators=(",", ":")
    )
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def decode_cursor(value: str) -> Cursor:
    invalid = ValidationFailed("The pagination cursor is invalid.")
    if not value or len(value) > MAX_CURSOR_CHARS:
        raise invalid
    try:
        padded = value + "=" * (-len(value) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        if not isinstance(data, dict) or set(data) != {"t", "i"}:
            raise invalid
        ts, raw_id = data["t"], data["i"]
        if not isinstance(ts, str) or not isinstance(raw_id, str):
            raise invalid
        created_at = datetime.fromisoformat(ts)
        if created_at.tzinfo is None or not (_MIN_YEAR <= created_at.year <= _MAX_YEAR):
            raise invalid
        return Cursor(created_at.astimezone(UTC), UUID(raw_id))
    except (ValueError, TypeError, UnicodeError, binascii.Error, OverflowError) as exc:
        raise invalid from exc


class PageQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    limit: int = Field(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE)
    cursor: str | None = Field(None, max_length=MAX_CURSOR_CHARS)

    def decoded(self) -> Cursor | None:
        return decode_cursor(self.cursor) if self.cursor else None


class Page[T](BaseModel):
    """A page of results plus the cursor for the next page (``None`` on the last page)."""

    model_config = ConfigDict(frozen=True)

    items: list[T]
    next_cursor: str | None = None
