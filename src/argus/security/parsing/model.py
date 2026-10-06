"""Types shared by the sandbox parent and the parser process (no parsing libraries here)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field

KINDS: Final = ("pdf", "docx", "text", "markdown", "csv", "json", "html")
MAX_TEXT_CHARS_CEILING: Final = 50_000_000


class ParseError(Exception):
    """The document cannot be parsed safely (permanent for this content)."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ParseLimits:
    max_input_bytes: int = 25 * 1024 * 1024
    max_pdf_pages: int = 2000
    max_archive_entries: int = 1000
    max_uncompressed_bytes: int = 100 * 1024 * 1024
    max_compression_ratio: int = 100
    max_json_depth: int = 64
    max_csv_field_bytes: int = 1024 * 1024
    max_csv_rows: int = 200_000
    max_text_chars: int = 5_000_000

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> ParseLimits:
        values = json.loads(raw)
        if not isinstance(values, dict) or not all(isinstance(v, int) for v in values.values()):
            msg = "invalid limits"
            raise ValueError(msg)
        return cls(**values)


class ParsedDocument(BaseModel):
    """Parser output. Validated with these bounds when it crosses back from the sandbox."""

    model_config = ConfigDict(extra="forbid")

    kind: str = Field(max_length=16)
    text: str = Field(max_length=MAX_TEXT_CHARS_CEILING)
    title: str | None = Field(None, max_length=1000)
    author: str | None = Field(None, max_length=1000)
    created_at: str | None = Field(None, max_length=64)
    language: str | None = Field(None, max_length=35)
    page_count: int | None = Field(None, ge=0, le=1_000_000)
    hidden_text: str = Field("", max_length=1_000_000)
    invisible_characters: int = Field(0, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list, max_length=50)
