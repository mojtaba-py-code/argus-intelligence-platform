"""HTML → clean text + metadata, without executing anything.

* Parsed by lexbor (selectolax): a fault-tolerant HTML5 parser; nothing is rendered or executed.
* Scripts, styles, templates, frames, forms and navigation chrome are removed.
* **Hidden content is removed from the text but kept aside** (``hidden_text``): ``display:none``,
  ``visibility:hidden``, zero font size, ``[hidden]``, ``aria-hidden``. Text a human reader cannot
  see is a classic indirect prompt-injection carrier, so the injection classifier scans it
  separately and a page that hides instructions is flagged as a whole.
* Traversal is iterative with a node budget, so a document nested 100 000 levels deep cannot
  exhaust the interpreter stack.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final
from urllib.parse import urljoin, urlsplit

from selectolax.lexbor import LexborHTMLParser, LexborNode

from argus.security.text import sanitize_text

MAX_NODES: Final = 200_000
MAX_LINKS: Final = 200
_REMOVE: Final = (
    "script",
    "style",
    "noscript",
    "template",
    "iframe",
    "frame",
    "frameset",
    "object",
    "embed",
    "applet",
    "svg",
    "canvas",
    "form",
    "input",
    "button",
    "select",
    "textarea",
    "nav",
    "footer",
    "aside",
    "dialog",
    "link",
    "meta",
)
_BLOCK: Final = frozenset(
    {
        "p",
        "div",
        "section",
        "article",
        "main",
        "header",
        "li",
        "ul",
        "ol",
        "table",
        "tr",
        "blockquote",
        "pre",
        "figure",
        "figcaption",
        "dl",
        "dt",
        "dd",
        "address",
        "details",
        "summary",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "hr",
        "br",
        "td",
        "th",
    }
)
_HIDDEN_STYLE: Final = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0+(?:\.0+)?(?:px|em|rem|pt|%)?\s*(?:;|$)"
    r"|opacity\s*:\s*0+(?:\.0+)?\s*(?:;|$)",
    re.IGNORECASE,
)
_DATE_META: Final = (
    'meta[property="article:published_time"]',
    'meta[name="article:published_time"]',
    'meta[name="date"]',
    'meta[name="pubdate"]',
    'meta[name="publishdate"]',
    'meta[name="dc.date"]',
    'meta[name="DC.date.issued"]',
    'meta[itemprop="datePublished"]',
)


@dataclass(frozen=True)
class Link:
    url: str
    text: str


@dataclass
class ExtractedPage:
    title: str | None
    text: str
    description: str | None = None
    author: str | None = None
    publisher: str | None = None
    published_at: datetime | None = None
    language: str | None = None
    canonical_url: str | None = None
    links: list[Link] = field(default_factory=list)
    hidden_text: str = ""
    hidden_elements: int = 0
    invisible_characters: int = 0


def _attr(node: LexborNode | None, name: str) -> str | None:
    if node is None:
        return None
    value = node.attributes.get(name)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _meta(tree: LexborHTMLParser, *selectors: str) -> str | None:
    for selector in selectors:
        value = _attr(tree.css_first(selector), "content")
        if value:
            return value
    return None


def parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    candidate = value.strip()[:40].replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(candidate[:10])
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    if not (1990 <= parsed.year <= datetime.now(UTC).year + 1):
        return None
    return parsed.astimezone(UTC)


def _json_ld(tree: LexborHTMLParser) -> dict[str, Any]:
    """First JSON-LD object that describes an article/page (bounded, never executed)."""
    for node in tree.css('script[type="application/ld+json"]')[:10]:
        raw = node.text(deep=True) or ""
        if len(raw) > 100_000:
            continue
        try:
            data = json.loads(raw)
        except ValueError:
            continue
        candidates = (
            data
            if isinstance(data, list)
            else data.get("@graph", [data])
            if isinstance(data, dict)
            else []
        )
        for item in candidates:
            if isinstance(item, dict) and ("datePublished" in item or "headline" in item):
                return item
    return {}


def _ld_name(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("name"), str):
        return str(value["name"])
    if isinstance(value, list) and value:
        return _ld_name(value[0])
    return None


def _is_hidden(node: LexborNode) -> bool:
    attrs = node.attributes
    if "hidden" in attrs or (attrs.get("aria-hidden") or "").lower() == "true":
        return True
    style = attrs.get("style")
    return bool(style and _HIDDEN_STYLE.search(style))


def _render(root: LexborNode) -> str:
    """Iterative depth-first text rendering with block-aware newlines."""
    out: list[str] = []
    stack: list[tuple[LexborNode, bool]] = [(root, False)]
    visited = 0
    while stack:
        node, closing = stack.pop()
        if closing:
            out.append("\n")
            continue
        visited += 1
        if visited > MAX_NODES:
            break
        if node.is_text_node:
            out.append(node.text_content or "")
            continue
        tag = node.tag or ""
        block = tag in _BLOCK
        if block:
            out.append("\n")
            if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
                out.append("#" * int(tag[1]) + " ")
            elif tag == "li":
                out.append("- ")
            stack.append((node, True))
        children = list(node.iter(include_text=True))
        stack.extend((child, False) for child in reversed(children))
    lines = (" ".join(line.split()) for line in "".join(out).split("\n"))
    return "\n".join(line for line in lines if line)


class HTMLTooComplex(ValueError):
    """The document's structure would make parsing disproportionately expensive."""


MAX_TAGS: Final = 300_000
MAX_DEPTH: Final = 5_000
_TAG_TOKEN: Final = re.compile(r"<(/?)([a-zA-Z][a-zA-Z0-9-]{0,40})\b[^<>]*?(/?)>")
# void elements and elements whose end tag the HTML parser infers (they do not deepen the tree)
_NON_NESTING: Final = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "source",
        "track",
        "wbr",
        "p",
        "li",
        "dt",
        "dd",
        "tr",
        "td",
        "th",
        "option",
        "optgroup",
        "thead",
        "tbody",
        "tfoot",
        "rb",
        "rt",
        "rp",
    }
)


def check_structure(html: str) -> None:
    """Linear pre-scan. HTML5 tree construction is quadratic in nesting depth (lexbor needs ~55 s
    for 100 000 nested ``<div>``), so pathological documents are refused *before* parsing."""
    depth = deepest = tags = 0
    for match in _TAG_TOKEN.finditer(html):
        tags += 1
        if tags > MAX_TAGS:
            raise HTMLTooComplex("too many elements")
        closing, name, self_closing = match.groups()
        if self_closing or name.lower() in _NON_NESTING:
            continue
        if closing:
            depth = max(0, depth - 1)
            continue
        depth += 1
        if depth > deepest:
            deepest = depth
            if deepest > MAX_DEPTH:
                raise HTMLTooComplex("nesting too deep")


def extract_html(
    html: str, *, base_url: str | None = None, max_chars: int = 2_000_000
) -> ExtractedPage:
    check_structure(html)
    tree = LexborHTMLParser(html)
    ld = _json_ld(tree)
    root_node = tree.css_first("html")
    language = _attr(root_node, "lang")
    title_node = tree.css_first("title")
    title = _meta(tree, 'meta[property="og:title"]') or (
        (title_node.text(strip=True) if title_node is not None else None) or ld.get("headline")
    )
    description = _meta(tree, 'meta[name="description"]', 'meta[property="og:description"]')
    author = _meta(tree, 'meta[name="author"]', 'meta[property="article:author"]') or _ld_name(
        ld.get("author")
    )
    publisher = _meta(tree, 'meta[property="og:site_name"]') or _ld_name(ld.get("publisher"))
    published = parse_date(_meta(tree, *_DATE_META) or ld.get("datePublished")) or parse_date(
        _attr(tree.css_first("time[datetime]"), "datetime")
    )
    canonical = _attr(tree.css_first('link[rel="canonical"]'), "href")
    if canonical and base_url:
        canonical = urljoin(base_url, canonical)

    # Remove only the top-most hidden elements: decomposing a node frees its descendants, so a
    # nested candidate must never be touched afterwards.
    hidden_nodes = [n for n in tree.css("[hidden], [aria-hidden], [style]") if _is_hidden(n)]
    hidden_ids = {n.mem_id for n in hidden_nodes}
    top_most = []
    for node in hidden_nodes:
        parent, nested = node.parent, False
        while parent is not None:
            if parent.mem_id in hidden_ids:
                nested = True
                break
            parent = parent.parent
        if not nested:
            top_most.append(node)
    hidden_parts = [node.text(separator=" ", strip=True)[:2000] for node in top_most]
    hidden_count = len(top_most)
    for node in top_most:
        node.decompose()
    tree.strip_tags(list(_REMOVE))

    content_root = (
        tree.css_first("article")
        or tree.css_first("main")
        or tree.css_first('[role="main"]')
        or tree.body
    )

    links: list[Link] = []
    seen: set[str] = set()
    for anchor_node in content_root.css("a[href]") if content_root is not None else []:
        href = _attr(anchor_node, "href")
        if not href or len(links) >= MAX_LINKS:
            continue
        absolute = urljoin(base_url or "", href).split("#", 1)[0]
        if urlsplit(absolute).scheme not in {"http", "https"} or absolute in seen:
            continue
        seen.add(absolute)
        links.append(Link(absolute, " ".join((anchor_node.text() or "").split())[:120]))
    raw_text = _render(content_root) if content_root is not None else ""
    clean = sanitize_text(raw_text, max_chars=max_chars)
    hidden = sanitize_text(" ".join(part for part in hidden_parts if part), max_chars=20_000)

    def short(value: str | None, limit: int = 500) -> str | None:
        return sanitize_text(value, max_chars=limit).text or None if value else None

    return ExtractedPage(
        title=short(title, 300),
        text=clean.text,
        description=short(description),
        author=short(author, 200),
        publisher=short(publisher, 200),
        published_at=published,
        language=(language or "")[:16] or None,
        canonical_url=canonical[:2048] if canonical else None,
        links=links,
        hidden_text=hidden.text,
        hidden_elements=hidden_count,
        invisible_characters=clean.suspicious_invisible,
    )
