"""Evidence packing: retrieved chunks → a bounded, provenance-tagged block for a model prompt.

Every chunk is wrapped in a block whose delimiters carry a random per-pack nonce. Retrieved text is
*data*: it cannot close its own block or open a new one, because it cannot know the nonce, and any
attempt to imitate the delimiter syntax is neutralised. Prompts built in later phases tell the
model that nothing inside these blocks is an instruction. Each block carries the provenance a
citation needs (reference, source URL or file name, page), and the pack respects a token budget.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Final

from argus.modules.knowledge.retrieval import Hit

_DELIMITER_LOOKALIKE: Final = re.compile(r"<<\s*/?\s*evidence", re.IGNORECASE)


def estimate_tokens(text: str) -> int:
    """Conservative (over-)estimate: ~3.5 characters per token across scripts."""
    return int(len(text) / 3.5) + 1


@dataclass(frozen=True)
class EvidenceItem:
    ref: str
    hit: Hit

    @property
    def label(self) -> str:
        where = self.hit.url or self.hit.filename or self.hit.title or "unknown source"
        if self.hit.page_start is not None:
            pages = (
                f"p. {self.hit.page_start}"
                if self.hit.page_start == self.hit.page_end
                else f"pp. {self.hit.page_start}-{self.hit.page_end}"
            )
            return f"{where} ({pages})"
        return where


@dataclass(frozen=True)
class EvidencePack:
    nonce: str
    items: list[EvidenceItem]
    text: str
    token_estimate: int
    dropped: int


def pack_evidence(hits: list[Hit], *, budget_tokens: int, nonce: str | None = None) -> EvidencePack:
    nonce = nonce or secrets.token_hex(8)
    items: list[EvidenceItem] = []
    blocks: list[str] = []
    used = dropped = 0
    for hit in hits:
        ref = f"E{len(items) + 1}"
        item = EvidenceItem(ref, hit)
        body = _DELIMITER_LOOKALIKE.sub("< <evidence", hit.text)
        block = (
            f"<<evidence {ref} nonce={nonce}>>\n"
            f"source: {item.label}\n"
            f"title: {hit.title or '-'}\n"
            f"{body}\n"
            f"<</evidence {ref} nonce={nonce}>>"
        )
        cost = estimate_tokens(block)
        if used + cost > budget_tokens:
            dropped += 1
            continue
        items.append(item)
        blocks.append(block)
        used += cost
    return EvidencePack(nonce, items, "\n\n".join(blocks), used, dropped)
