"""Paragraph-aware chunking with exact character offsets and page numbers.

Text is split into *units* - paragraphs, then sentences for long paragraphs, then whitespace-aware
windows for very long sentences - and units are packed into windows of about ``target`` characters.
Each chunk after the first starts up to ``overlap`` characters before the previous one ended, at a
sentence or word boundary, so an answer that straddles a boundary is still retrievable. Each chunk's text is an exact slice of the source text,
which is what lets a citation point at a page and a character range. Linear in the input size.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass
from typing import Final

_PARAGRAPH_BREAK: Final = re.compile(r"\n[ \t]*\n")
# Sentence ends: Latin, CJK full stop (U+3002), Arabic question mark (U+061F) and full stop (U+06D4).
_SENTENCE_END: Final = re.compile(r"(?<=[.!?" + chr(0x3002) + chr(0x061F) + chr(0x06D4) + r"])\s+")
MAX_CHUNKS: Final = 50_000


@dataclass(frozen=True)
class TextChunk:
    ordinal: int
    text: str
    char_start: int
    char_end: int
    page_start: int | None = None
    page_end: int | None = None

    @property
    def token_estimate(self) -> int:
        return len(self.text) // 4 + 1


def _trimmed(text: str, start: int, end: int) -> tuple[int, int] | None:
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return (start, end) if end > start else None


def _windows(text: str, start: int, end: int, size: int) -> list[tuple[int, int]]:
    """Hard split of an over-long span, preferring to break at whitespace."""
    spans: list[tuple[int, int]] = []
    while end - start > size:
        cut = text.rfind(" ", start + size // 2, start + size)
        cut = cut if cut > start else start + size
        spans.append((start, cut))
        start = cut
    spans.append((start, end))
    return [span for s, e in spans if (span := _trimmed(text, s, e)) is not None]


def _units(text: str, size: int) -> list[tuple[int, int]]:
    units: list[tuple[int, int]] = []
    position = 0
    for match in [*_PARAGRAPH_BREAK.finditer(text), None]:
        end = match.start() if match is not None else len(text)
        paragraph = _trimmed(text, position, end)
        position = match.end() if match is not None else len(text)
        if paragraph is None:
            continue
        p_start, p_end = paragraph
        if p_end - p_start <= size:
            units.append(paragraph)
            continue
        sentence_start = p_start
        for boundary in [*_SENTENCE_END.finditer(text, p_start, p_end), None]:
            s_end = boundary.start() if boundary is not None else p_end
            sentence = _trimmed(text, sentence_start, s_end)
            sentence_start = boundary.end() if boundary is not None else p_end
            if sentence is not None:
                units.extend(_windows(text, *sentence, size))
    return units


def _page(offsets: list[int], position: int) -> int:
    return max(1, bisect_right(offsets, position))


def _overlap_start(text: str, chunk_start: int, end: int, overlap: int) -> int | None:
    """Where the next chunk begins: within the last ``overlap`` characters of the previous one,
    at a sentence boundary if there is one, otherwise at a word boundary (never mid-word)."""
    if overlap <= 0:
        return None
    window_start = max(chunk_start + 1, end - overlap)
    sentence = _SENTENCE_END.search(text, window_start, end)
    if sentence is not None and sentence.end() < end:
        return sentence.end()
    for index in range(window_start, end):
        if text[index].isspace():
            return index + 1 if index + 1 < end else None
    return None


def chunk_text(
    text: str,
    *,
    target: int = 1200,
    overlap: int = 180,
    page_offsets: list[int] | None = None,
) -> list[TextChunk]:
    if overlap * 2 > target:
        msg = "overlap must be at most half of the target size"
        raise ValueError(msg)
    offsets = sorted(page_offsets) if page_offsets else None
    chunks: list[TextChunk] = []
    current: list[tuple[int, int]] = []

    def emit() -> None:
        start, end = current[0][0], current[-1][1]
        chunks.append(
            TextChunk(
                ordinal=len(chunks),
                text=text[start:end],
                char_start=start,
                char_end=end,
                page_start=_page(offsets, start) if offsets else None,
                page_end=_page(offsets, end - 1) if offsets else None,
            )
        )

    minimum = target // 4  # a lone heading is merged with what follows, not emitted alone
    for unit in _units(text, target):
        span = current[-1][1] - current[0][0] if current else 0
        if current and unit[1] - current[0][0] > target and span >= minimum:
            emit()
            if len(chunks) >= MAX_CHUNKS:
                return chunks
            start = _overlap_start(text, current[0][0], current[-1][1], overlap)
            tail = _trimmed(text, start, current[-1][1]) if start is not None else None
            current = [tail] if tail is not None else []
        current.append(unit)
    if current:
        emit()
    return chunks
