"""Change detection: what really changed between two snapshots, and does it matter?

Pages change constantly in ways nobody cares about - timestamps, "5 minutes ago", view counters,
copyright years, cache-busting tokens. Lines are compared after those volatile parts are
replaced by placeholders, so a page whose only difference is the clock produces no diff at all.

Significance is computed by code from three signals: how much of the page changed, whether the
change touches a topic the monitor watches (pricing, funding, people, jobs...), and whether
figures changed. A monitoring agent may refine the score; code decides the floor below which no
model is consulted and no alert is ever sent.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final

from argus.modules.research.evidence import numbers
from argus.security.text import sanitize_text

MAX_LINES: Final = 5000
MAX_EXCERPT_LINES: Final = 20
MAX_LINE_CHARS: Final = 300

_MONTHS: Final = (
    "jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|"
    "sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?"
)
_VOLATILE: Final = tuple(
    (re.compile(pattern, re.IGNORECASE), placeholder)
    for pattern, placeholder in (
        (r"\b\d+\s+(?:second|minute|hour|day|week|month|year)s?\s+ago\b", "<ago>"),
        (
            r"\b\d{4}-\d{2}-\d{2}(?:[t ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:z|[+-]\d{2}:?\d{2})?)?\b",
            "<date>",
        ),
        (rf"\b(?:{_MONTHS})\.?\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{4}}\b", "<date>"),
        (rf"\b\d{{1,2}}\s+(?:{_MONTHS})\.?,?\s+\d{{4}}\b", "<date>"),
        (r"\b\d{1,2}/\d{1,2}/\d{2,4}\b", "<date>"),
        (r"\b\d{1,2}:\d{2}(?::\d{2})?\s*(?:am|pm|utc|gmt)?\b", "<time>"),
        (r"(?:©|\(c\)|copyright)\s*\d{4}(?:\s*[-\u2013]\s*\d{4})?", "<copyright>"),
        (
            (
                r"\b\d[\d,.]*\s*[km]?\s+(?:views?|likes?|comments?|shares?|followers?|readers?|"
                r"visits?|downloads?|stars?|reviews?)\b"
            ),
            "<counter>",
        ),
        (r"\b[0-9a-f]{16,}\b", "<token>"),
    )
)
TOPIC_PATTERNS: Final[dict[str, re.Pattern[str]]] = {
    topic: re.compile(pattern, re.IGNORECASE)
    for topic, pattern in {
        "pricing": (
            r"\b(?:prices?|pricing|per\s+(?:month|year|user|seat)|plans?|tiers?|discounts?|"
            r"subscriptions?|free\s+trial|usd|eur|gbp)\b|[$€£]\s?\d"
        ),
        "funding": (
            r"\b(?:raised|raises|funding|series\s+[a-f]|seed\s+round|investors?|valuation|"
            r"acquired|acquisition|ipo)\b"
        ),
        "jobs": r"\b(?:hiring|careers?|jobs?|positions?|openings?|vacanc(?:y|ies)|apply\s+now)\b",
        "people": (
            r"\b(?:ceo|cto|cfo|coo|chief\s+\w+\s+officer|vice\s+president|head\s+of|joins|"
            r"joined|appointed|steps?\s+down|board\s+of\s+directors)\b"
        ),
        "product": (
            r"\b(?:launch(?:es|ed)?|releases?|released|features?|products?|versions?|beta|"
            r"general\s+availability|now\s+available)\b"
        ),
        "technology": (
            r"\b(?:api|sdk|integrations?|platform|models?|architecture|cloud|open[\s-]source|"
            r"infrastructure)\b"
        ),
        "news": r"\b(?:announces?|announced|press\s+release|partnership|news)\b",
    }.items()
}


def _normalise(line: str) -> str:
    folded = unicodedata.normalize("NFKC", line).casefold()
    for pattern, placeholder in _VOLATILE:
        folded = pattern.sub(placeholder, folded)
    return " ".join(folded.split())


def _lines(text: str) -> list[str]:
    clean = sanitize_text(text).text
    lines = [" ".join(line.split()) for line in clean.split("\n")]
    return [line for line in lines if line][:MAX_LINES]


@dataclass(frozen=True)
class Diff:
    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed_ratio: float
    """Changed characters relative to the larger version (0 = identical, 1 = everything)."""

    @property
    def empty(self) -> bool:
        return not self.added and not self.removed

    def excerpt(self) -> dict[str, list[str]]:
        return {
            "added": [line[:MAX_LINE_CHARS] for line in self.added[:MAX_EXCERPT_LINES]],
            "removed": [line[:MAX_LINE_CHARS] for line in self.removed[:MAX_EXCERPT_LINES]],
        }


def diff(old_text: str, new_text: str) -> Diff:
    old = {_normalise(line): line for line in _lines(old_text)}
    new = {_normalise(line): line for line in _lines(new_text)}
    added = tuple(line for key, line in new.items() if key not in old)
    removed = tuple(line for key, line in old.items() if key not in new)
    changed = sum(len(line) for line in added) + sum(len(line) for line in removed)
    size = max(sum(map(len, old.values())), sum(map(len, new.values())), 1)
    return Diff(added, removed, round(min(1.0, changed / size), 4))


def matched_topics(change: Diff, watched: Iterable[str]) -> list[str]:
    """Watched topics the change touches; ``website`` matches any change."""
    watched = list(watched) or [*TOPIC_PATTERNS, "website"]
    text = "\n".join((*change.added, *change.removed))
    found = [t for t in watched if t in TOPIC_PATTERNS and TOPIC_PATTERNS[t].search(text)]
    if "website" in watched and not change.empty:
        found.append("website")
    return found


def significance(change: Diff, watched: Sequence[str]) -> tuple[float, list[str]]:
    """Code's significance score in [0, 1] and the topics behind it."""
    if change.empty:
        return 0.0, []
    topics = matched_topics(change, watched)
    specific = [t for t in topics if t != "website"]
    figures = numbers(" ".join(change.added)) ^ numbers(" ".join(change.removed))
    score = (
        0.1
        + 0.4 * min(1.0, change.changed_ratio * 2)
        + (0.35 if specific else 0.1 if topics else 0.0)
        + (0.15 if figures else 0.0)
    )
    return round(min(1.0, score), 3), topics
