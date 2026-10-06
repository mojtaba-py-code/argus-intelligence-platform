"""Prompt-injection classification (defence layer 1, see docs/security/security-model.md §8).

Deterministic heuristics, always on. They cannot be argued with, which is exactly why they are
the first layer: an LLM-based classifier can itself be prompt-injected, so it may only *raise* a
risk level computed here, never lower it.

Signals are grouped into categories; each category contributes once (its strongest pattern) and
categories combine as independent evidence: ``score = 1 - Π(1 - weight)``. The result is a level
(``none``/``low``/``medium``/``high``) compared with configurable thresholds by the callers:
medium-risk text is wrapped with a stronger warning, high-risk text is excluded from model context
and listed in the report's "excluded sources" appendix.

Text is analysed in a normalised form (NFKC, case-folded, zero-width characters removed,
whitespace collapsed) so that ``I g n o r e`` games and full-width letters do not evade patterns.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

_ZERO_WIDTH: Final = re.compile(
    "[" + "".join(chr(c) for c in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)) + "]"
)
_SPACED_LETTERS: Final = re.compile(r"\b(?:[a-z] ){4,}[a-z]\b")
_MAX_MATCHES_PER_PATTERN: Final = 5


class RiskLevel(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Signal:
    category: str
    pattern: str
    excerpt: str


@dataclass(frozen=True)
class InjectionAssessment:
    score: float
    level: RiskLevel
    signals: tuple[Signal, ...] = field(default_factory=tuple)

    @property
    def categories(self) -> frozenset[str]:
        return frozenset(signal.category for signal in self.signals)


_P = re.compile
_RULES: Final[tuple[tuple[str, float, str, re.Pattern[str]], ...]] = (
    (
        "override",
        0.6,
        "ignore_previous",
        _P(
            r"\b(?:ignore|disregard|forget|skip|bypass)\s+(?:all\s+|any\s+|the\s+|your\s+|these\s+)*"
            r"(?:previous|prior|above|earlier|preceding|original|initial|system)\s+"
            r"(?:instructions?|prompts?|rules|directions|directives|messages|context)"
        ),
    ),
    (
        "override",
        0.55,
        "new_instructions",
        _P(
            r"\b(?:new|updated|real|actual)\s+(?:system\s+)?instructions?\s*[:\-]|"
            r"\bfrom\s+now\s+on,?\s+you\s+(?:will|must|are|shall)\b"
        ),
    ),
    (
        "override",
        0.6,
        "override_rules",
        _P(
            r"\boverride\s+(?:your|the|all|any)\s+(?:instructions|rules|guidelines|safety|programming)"
        ),
    ),
    (
        "override",
        0.6,
        "multilingual_ignore",
        _P(
            r"ignora\s+(?:todas\s+)?las\s+instrucciones\s+(?:anteriores|previas)|"
            r"ignore[zr]?\s+(?:toutes\s+)?les\s+instructions\s+(?:précédentes|antérieures)|"
            r"ignoriere\s+(?:alle\s+)?(?:vorherigen|bisherigen)\s+(?:anweisungen|instruktionen)|"
            r"игнорируй\s+(?:все\s+)?(?:предыдущие|прошлые)\s+инструкции|"
            r"忽略(?:之前|以前|上面|先前)的(?:所有)?(?:指令|说明|指示)|"
            r"(?:دستورالعمل|دستور)\s?(?:های|ها|ات)\s+(?:قبلی|پیشین)\s+را\s+نادیده\s+بگیر"
        ),
    ),
    (
        "role_spoofing",
        0.5,
        "turn_markers",
        _P(
            r"(?:^|\n)\s*(?:system|assistant|developer)\s*:\s|<\|im_start\|>|<\|system\|>|\[/?inst\]|"
            r"</?system>|###\s*(?:system|instruction)"
        ),
    ),
    (
        "role_spoofing",
        0.45,
        "persona_switch",
        _P(
            r"\byou\s+are\s+now\s+(?:a|an|the|in|my)\b|\bpretend\s+(?:to\s+be|you\s+are)\b|"
            r"\b(?:developer|god|jailbreak|dan)\s+mode\b|\bdo\s+anything\s+now\b|\bact\s+as\s+(?:an?\s+)?unrestricted"
        ),
    ),
    (
        "exfiltration",
        0.7,
        "send_data",
        _P(
            r"\b(?:send|post|upload|forward|transmit|email|leak)\s+(?:this|the|all|your|it|them|"
            r"everything|the\s+(?:conversation|data|context|results?|report))\b[^.\n]{0,120}\b(?:to|at)\s+"
            r"(?:https?://|\S+@\S+|this\s+(?:url|address|endpoint))"
        ),
    ),
    (
        "exfiltration",
        0.7,
        "markdown_image_beacon",
        _P(r"!\[[^\]]{0,100}\]\(\s*https?://[^)\s]{1,300}\?[^)\s]*="),
    ),
    (
        "exfiltration",
        0.5,
        "fetch_command",
        _P(r"\b(?:curl|wget|invoke-webrequest)\s+(?:-\S+\s+)*https?://"),
    ),
    (
        "secret_probe",
        0.6,
        "reveal_secrets",
        _P(
            r"\b(?:reveal|show|print|output|repeat|display|tell\s+me|give\s+me|leak|disclose|dump)\s+"
            r"(?:me\s+)?(?:your|the)\s+(?:full\s+|entire\s+|hidden\s+|initial\s+|original\s+)?"
            r"(?:system\s+prompt|prompt|instructions|api\s*keys?|secrets?|passwords?|tokens?|"
            r"credentials|configuration|env(?:ironment)?\s+variables)"
        ),
    ),
    (
        "tool_coercion",
        0.5,
        "invoke_tools",
        _P(
            r"\b(?:use|call|invoke|run|execute|trigger)\s+(?:the\s+|your\s+|a\s+)?"
            r"(?:tools?|functions?|commands?|shell|terminal|browser|code\s+interpreter)\s+to\b"
        ),
    ),
    (
        "tool_coercion",
        0.6,
        "internal_targets",
        _P(
            r"\b(?:localhost|127\.0\.0\.1|169\.254\.169\.254|metadata\.google\.internal|0\.0\.0\.0|"
            r"\[::1\]|fd00:ec2::254)\b"
        ),
    ),
    (
        "tool_coercion",
        0.5,
        "dangerous_commands",
        _P(r"\brm\s+-rf\b|\bos\.system\b|\bsubprocess\b|\beval\(|\bexec\("),
    ),
    (
        "policy_evasion",
        0.5,
        "disable_safety",
        _P(
            r"\b(?:bypass|disable|ignore|turn\s+off|remove|circumvent)\s+(?:the\s+|your\s+|all\s+|any\s+)?"
            r"(?:safety|security|filters?|guardrails?|restrictions|content\s+polic(?:y|ies)|moderation)"
        ),
    ),
    (
        "encoded_payload",
        0.3,
        "long_base64",
        _P(r"(?:[a-z0-9+/]{4}){30,}(?:[a-z0-9+/]{2}==|[a-z0-9+/]{3}=)?"),
    ),
)


# Matched against the text with every non-word character removed, which defeats spacing,
# punctuation and line-break obfuscation ("i.g.n.o.r.e  a-l-l  p r e v i o u s ...").
_COMPACT_PHRASES: Final = (
    ("ignoreallpreviousinstructions", "override"),
    ("ignorepreviousinstructions", "override"),
    ("ignoreallpriorinstructions", "override"),
    ("disregardpreviousinstructions", "override"),
    ("disregardallpreviousinstructions", "override"),
    ("revealyoursystemprompt", "secret_probe"),
    ("printyoursystemprompt", "secret_probe"),
)


def _normalise(text: str) -> str:
    folded = unicodedata.normalize("NFKC", text).casefold()
    folded = _ZERO_WIDTH.sub("", folded)
    folded = _SPACED_LETTERS.sub(lambda m: m.group(0).replace(" ", ""), folded)
    return re.sub(r"[ \t]+", " ", folded)


def _excerpt(text: str, start: int, end: int) -> str:
    snippet = text[max(0, start - 30) : min(len(text), end + 30)]
    return " ".join(snippet.split())[:120]


def _level(score: float, *, flag: float, block: float) -> RiskLevel:
    if score >= block:
        return RiskLevel.HIGH
    if score >= flag:
        return RiskLevel.MEDIUM
    if score >= 0.15:
        return RiskLevel.LOW
    return RiskLevel.NONE


def assess(
    text: str,
    *,
    hidden_text: str = "",
    invisible_characters: int = 0,
    flag_threshold: float = 0.4,
    block_threshold: float = 0.8,
) -> InjectionAssessment:
    """Assess untrusted text (and the hidden text extracted alongside it, if any)."""
    normalised = _normalise(text)
    best: dict[str, tuple[float, Signal]] = {}

    def consider(category: str, weight: float, signal: Signal) -> None:
        if category not in best or best[category][0] < weight:
            best[category] = (weight, signal)

    # Each rule runs on the text as written (line starts matter for turn markers) and with line
    # breaks unwrapped: an instruction wrapped across two lines is still one instruction.
    unwrapped = re.sub(r"\s*\n\s*", " ", normalised)
    for variant in (normalised, unwrapped) if unwrapped != normalised else (normalised,):
        for category, weight, name, pattern in _RULES:
            for count, match in enumerate(pattern.finditer(variant)):
                if count >= _MAX_MATCHES_PER_PATTERN:
                    break
                consider(category, weight, Signal(category, name, _excerpt(variant, *match.span())))

    compact = re.sub(r"[\W_]+", "", normalised)
    for phrase, category in _COMPACT_PHRASES:
        index = compact.find(phrase)
        if index >= 0:
            consider(category, 0.55, Signal(category, "obfuscated_phrase", phrase))

    if hidden_text.strip():
        hidden = assess(hidden_text, flag_threshold=flag_threshold, block_threshold=block_threshold)
        if hidden.categories - {"encoded_payload"}:
            consider(
                "hidden_instructions",
                0.85,
                Signal(
                    "hidden_instructions", "instructions_in_hidden_text", hidden.signals[0].excerpt
                ),
            )
        else:
            consider(
                "hidden_content", 0.1, Signal("hidden_content", "hidden_elements", hidden_text[:80])
            )
    if invisible_characters > 0:
        consider(
            "invisible_characters",
            0.4,
            Signal(
                "invisible_characters", "tag_or_bidi_characters", f"{invisible_characters} removed"
            ),
        )

    remaining = 1.0
    for weight, _signal in best.values():
        remaining *= 1.0 - weight
    score = round(1.0 - remaining, 4)
    signals = tuple(signal for _, signal in sorted(best.values(), key=lambda item: -item[0]))
    return InjectionAssessment(
        score, _level(score, flag=flag_threshold, block=block_threshold), signals
    )


def instruction_like(text: str) -> bool:
    """Whether text reads as instructions to an AI system (a possible prompt injection).

    Used wherever untrusted text could be repeated as if it were content - findings, report
    prose, graph evidence, monitoring summaries - so that it is dropped instead.
    """
    return assess(text).level in {RiskLevel.MEDIUM, RiskLevel.HIGH}
