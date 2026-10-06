"""Normalisation of untrusted text before it is stored, indexed or shown to a model.

Removed (no legitimate use in research text, frequently used to hide instructions or to make text
display differently from how it is processed - "Trojan Source"):

* C0/C1 control characters (except newline and tab), DEL;
* bidirectional *embeddings, overrides and isolates* (U+202A-U+202E, U+2066-U+2069);
* Unicode TAG characters (U+E0000-U+E007F) - invisible "ASCII smuggling" carriers;
* invisible math operators and word joiner (U+2060-U+2064), interlinear annotations
  (U+FFF9-U+FFFB), and stray byte-order marks.

Deliberately **kept**: ZERO WIDTH NON-JOINER (U+200C) and ZERO WIDTH JOINER (U+200D), which are
required to write Persian, Arabic and Indic scripts and emoji correctly; left-to-right/right-to-left
*marks* (U+200E, U+200F) used in mixed-direction text. ZERO WIDTH SPACE (U+200B) is kept (Thai,
Khmer) but counted, because dense runs of it inside Latin text are an obfuscation signal.

Code points are written with ``chr()`` on purpose: literal invisible characters in source files
are themselves a review hazard.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Final

_C0_C1: Final = "".join(
    chr(c) for c in (*range(0x09), 0x0B, 0x0C, *range(0x0E, 0x20), *range(0x7F, 0xA0))
)
_BIDI_CONTROLS: Final = "".join(chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)))
_INVISIBLE_OPERATORS: Final = "".join(chr(c) for c in range(0x2060, 0x2065))
_ANNOTATIONS: Final = "".join(chr(c) for c in range(0xFFF9, 0xFFFC))
_BOM: Final = chr(0xFEFF)
_ZWSP: Final = chr(0x200B)

_RE_CONTROL: Final = re.compile(f"[{re.escape(_C0_C1)}]")
_RE_BIDI: Final = re.compile(f"[{re.escape(_BIDI_CONTROLS)}]")
_RE_INVISIBLE: Final = re.compile(f"[{re.escape(_INVISIBLE_OPERATORS + _ANNOTATIONS + _BOM)}]")
_RE_TAGS: Final = re.compile(f"[{chr(0xE0000)}-{chr(0xE007F)}]")
_RE_SURROGATES: Final = re.compile(f"[{chr(0xD800)}-{chr(0xDFFF)}]")
_RE_SPACES: Final = re.compile(r"[ \t]{2,}")
_RE_BLANK_LINES: Final = re.compile(r"\n{3,}")
_VISIBLE: Final = frozenset("LMNPS")  # Unicode major categories that render something


@dataclass(frozen=True)
class SanitizedText:
    text: str
    removed: dict[str, int] = field(default_factory=dict)
    zero_width_spaces: int = 0

    @property
    def suspicious_invisible(self) -> int:
        return (
            self.removed.get("tag_characters", 0)
            + self.removed.get("bidi_controls", 0)
            + (self.zero_width_spaces if self.zero_width_spaces > 20 else 0)
        )


def sanitize_text(raw: str, *, max_chars: int | None = None) -> SanitizedText:
    removed: dict[str, int] = {}
    # Lone surrogates cannot be encoded as UTF-8 (a malformed PDF string is enough to get one).
    text, surrogates = _RE_SURROGATES.subn(chr(0xFFFD), raw)
    if surrogates:
        removed["surrogates"] = surrogates
    text = unicodedata.normalize("NFC", text.replace("\r\n", "\n").replace("\r", "\n"))
    for name, pattern in (
        ("tag_characters", _RE_TAGS),
        ("bidi_controls", _RE_BIDI),
        ("invisible_characters", _RE_INVISIBLE),
        ("control_characters", _RE_CONTROL),
    ):
        text, count = pattern.subn("", text)
        if count:
            removed[name] = count
    zero_width = text.count(_ZWSP)
    text = _RE_SPACES.sub(" ", text)
    text = _RE_BLANK_LINES.sub("\n\n", text).strip()
    if max_chars is not None and len(text) > max_chars:
        text = text[:max_chars]
        removed["truncated_chars"] = len(raw) - max_chars
    return SanitizedText(text, removed, zero_width)


def clean_line(value: str | None, limit: int) -> str | None:
    """A single-line display value (title, author): sanitised, whitespace collapsed, bounded.

    Untrusted metadata reaches length-limited database columns through this; ``None`` when empty.
    """
    if not value:
        return None
    line = " ".join(sanitize_text(value).text.split())[:limit]
    # A value with nothing visible (only zero-width or format characters) would display blank.
    if not any(unicodedata.category(ch)[0] in _VISIBLE for ch in line):
        return None
    return line
