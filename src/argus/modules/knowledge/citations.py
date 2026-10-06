"""Evidence ids and mechanical citation checks, shared by answers and research findings.

A model's citation is accepted only if the quoted text really appears - after Unicode, case and
whitespace normalisation - in a chunk the model was actually given under that id. This catches
invented quotes and mis-attributed sources without asking another model.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable
from typing import Final
from uuid import UUID

from argus.core.classification import Classification
from argus.modules.knowledge.retrieval import Hit
from argus.modules.llm.types import UntrustedData

MIN_QUOTE_CHARS: Final = 8


def normalise(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def quote_supported(quote: str, texts: Iterable[str]) -> bool:
    needle = normalise(quote)
    return len(needle) >= MIN_QUOTE_CHARS and any(needle in normalise(text) for text in texts)


def describe(hit: Hit) -> str:
    where = hit.url or hit.filename or hit.title or "unknown source"
    if hit.page_start is not None:
        pages = (
            f"p. {hit.page_start}"
            if hit.page_start == hit.page_end
            else f"pp. {hit.page_start}-{hit.page_end}"
        )
        return f"{where} ({pages})"
    return where


class EvidenceRegistry:
    """Stable ids (E1, E2, ...) for retrieved chunks across an agent's iterations; no duplicates."""

    def __init__(self) -> None:
        self._items: dict[str, Hit] = {}
        self._chunks: set[UUID] = set()

    def add(self, hits: Iterable[Hit]) -> list[UntrustedData]:
        parts: list[UntrustedData] = []
        for hit in hits:
            if hit.chunk_id in self._chunks:
                continue
            ref = f"E{len(self._items) + 1}"
            self._items[ref] = hit
            self._chunks.add(hit.chunk_id)
            parts.append(
                UntrustedData(
                    text=f"source: {describe(hit)}\ntitle: {hit.title or '-'}\n\n{hit.text}",
                    label=ref,
                    classification=Classification(hit.classification),
                )
            )
        return parts

    def get(self, ref: str) -> Hit | None:
        return self._items.get(ref)

    @property
    def max_classification(self) -> Classification:
        return max(
            (Classification(hit.classification) for hit in self._items.values()),
            default=Classification.PUBLIC,
        )

    def __len__(self) -> int:
        return len(self._items)
