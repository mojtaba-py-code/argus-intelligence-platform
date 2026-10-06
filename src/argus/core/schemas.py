"""Base classes and strict field types for API and service schemas.

Requests reject unknown fields (``extra="forbid"``) and use strict scalar types where coercion is
dangerous: with lax parsing ``{"approve": 0}`` or ``{"approve": "no"}`` silently becomes a bool and
``"5"`` an int, turning client bugs into wrong decisions.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, Strict

StrictBool = Annotated[bool, Strict()]
StrictInt = Annotated[int, Strict()]
StrictFloat = Annotated[float, Strict()]

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BIDI_OVERRIDES = frozenset(chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)))


def clean_text(value: str) -> str:
    """NFC-normalise and reject control and bidi-override characters (Trojan-Source style)."""
    value = unicodedata.normalize("NFC", value)
    if _CONTROL.search(value) or any(ch in _BIDI_OVERRIDES for ch in value):
        msg = "contains control characters"
        raise ValueError(msg)
    return value


def _single_line(value: str) -> str:
    value = clean_text(value).strip()
    if "\n" in value or "\r" in value or "\t" in value:
        msg = "must be a single line"
        raise ValueError(msg)
    return value


Name = Annotated[str, Field(min_length=1, max_length=200), AfterValidator(_single_line)]
ShortText = Annotated[str, Field(min_length=1, max_length=200), AfterValidator(_single_line)]
LongText = Annotated[str, Field(max_length=4000), AfterValidator(clean_text)]
Secret = Annotated[str, Field(min_length=1, max_length=1024)]
Token = Annotated[str, Field(min_length=16, max_length=512, pattern=r"^[A-Za-z0-9_\-]+$")]


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ResponseModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True)
