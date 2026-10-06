"""Document parsers. They run ONLY inside the sandbox process (:mod:`.worker`).

Written for hostile input: every loop is bounded; XML goes through defusedxml (no DTDs, no entity
expansion, no external references); ZIP containers are vetted from the central directory before
any member is read (entry count, declared sizes, compression ratio, paths, encryption); JSON
nesting is measured with a linear scan before ``json.loads`` can recurse; regular expressions are
linear; and every output is capped. Text that a reader would not see - hidden Word runs, HTML
comments in Markdown, hidden HTML elements - is separated into ``hidden_text``: it is evidence
for the prompt-injection assessment, not content.
"""

from __future__ import annotations

import csv
import io
import json
import re
import zipfile
import zlib
from collections.abc import Callable
from datetime import datetime
from typing import Any, Final

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError as XMLParseError
from defusedxml.ElementTree import iterparse
from pypdf import PdfReader

from argus.security.html import HTMLTooComplex, extract_html
from argus.security.parsing.model import ParsedDocument, ParseError, ParseLimits
from argus.security.text import sanitize_text

_PAGE_BREAK: Final = "\n\n"
# Names of PDF features that run code, launch programs or carry files. Best effort: they can hide
# inside compressed object streams. (/OpenAction alone is common and usually just sets the zoom.)
_ACTIVE_PDF: Final = re.compile(
    rb"/(JavaScript|JS|Launch|EmbeddedFiles?|RichMedia|XFA|SubmitForm)(?=[\s/<>\[\]()%]|$)"
)
_W: Final = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_DC: Final = "{http://purl.org/dc/elements/1.1/}"
_DCTERMS: Final = "{http://purl.org/dc/terms/}"
_FALSE: Final = frozenset({"0", "false", "off"})
_JSON_STRING: Final = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"', re.DOTALL)
_BRACKETS: Final = re.compile(r"[\[\]{}]")
_MAX_KEY_IN_PATH: Final = 64
_MAX_COLUMNS: Final = 1000


def _decode(data: bytes) -> str:
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


def _short(value: object, limit: int = 300) -> str | None:
    if value is None:
        return None
    text = " ".join(sanitize_text(str(value)).text.split())[:limit]
    return text or None


# ---------------------------------------------------------------------------------- PDF
def parse_pdf(data: bytes, limits: ParseLimits) -> ParsedDocument:
    warnings: list[str] = []
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            try:
                unlocked = reader.decrypt("")
            except Exception:  # noqa: BLE001 - any failure here means "cannot open"
                raise ParseError("encrypted", "the PDF is encrypted") from None
            if not unlocked:
                raise ParseError("encrypted", "the PDF is password-protected")
        page_count = len(reader.pages)
        if page_count > limits.max_pdf_pages:
            raise ParseError("too_many_pages", f"{page_count} pages, limit {limits.max_pdf_pages}")
        pages: list[str] = []
        offsets: list[int] = []
        total = 0
        for page in reader.pages:
            offsets.append(total)
            # Sanitised per page so the offsets stay exact after the final pass (idempotent).
            text = sanitize_text(page.extract_text() or "").text
            pages.append(text)
            total += len(text) + len(_PAGE_BREAK)
            if total > limits.max_text_chars:
                warnings.append("text_truncated")
                break
        info = reader.metadata
        title = author = created = None
        if info is not None:
            title, author = _short(info.title), _short(info.author)
            try:
                created = info.creation_date.isoformat() if info.creation_date else None
            except (ValueError, TypeError):
                created = None
    except ParseError:
        raise
    except Exception as exc:  # noqa: BLE001 - malformed PDFs raise anything; all mean "corrupt"
        raise ParseError("corrupt_pdf", type(exc).__name__) from None
    active = sorted({m.group(1).decode() for m in _ACTIVE_PDF.finditer(data)})
    return ParsedDocument(
        kind="pdf",
        text=_PAGE_BREAK.join(pages),
        title=title,
        author=author,
        created_at=created,
        page_count=page_count,
        metadata={"page_offsets": offsets, "active_content": active},
        warnings=warnings,
    )


# ---------------------------------------------------------------------------------- ZIP
def vet_archive(archive: zipfile.ZipFile, limits: ParseLimits) -> None:
    """Reject zip bombs and hostile entries using only the central directory."""
    infos = archive.infolist()
    if len(infos) > limits.max_archive_entries:
        raise ParseError("archive_too_many_entries", str(len(infos)))
    total = 0
    for info in infos:
        name = info.filename
        segments = name.replace("\\", "/").split("/")
        if name.startswith(("/", "\\")) or ".." in segments or ":" in name or "\x00" in name:
            raise ParseError("archive_bad_path")
        if info.flag_bits & 0x1:
            raise ParseError("archive_encrypted")
        total += info.file_size
        if total > limits.max_uncompressed_bytes:
            raise ParseError("archive_too_large")
        if info.file_size > 1024 * 1024 and info.file_size > limits.max_compression_ratio * max(
            1, info.compress_size
        ):
            raise ParseError("archive_ratio", name[:100])


def _read_member(archive: zipfile.ZipFile, name: str, limits: ParseLimits) -> bytes:
    info = archive.getinfo(name)
    if info.file_size > limits.max_uncompressed_bytes:
        raise ParseError("archive_too_large")
    try:
        with archive.open(info) as handle:
            # zipfile never yields more than the declared size and verifies the CRC at the end.
            data = handle.read(info.file_size + 1)
    except (zipfile.BadZipFile, zlib.error, EOFError, OSError, NotImplementedError) as exc:
        raise ParseError("corrupt_archive", type(exc).__name__) from None
    if len(data) > info.file_size:
        raise ParseError("archive_size_mismatch")
    return data


# --------------------------------------------------------------------------------- DOCX
def _run_hidden(properties: Any) -> bool:
    for flag in (f"{_W}vanish", f"{_W}specVanish"):
        element = properties.find(flag)
        if element is not None and element.get(f"{_W}val", "true").lower() not in _FALSE:
            return True
    size = properties.find(f"{_W}sz")
    value = size.get(f"{_W}val", "") if size is not None else ""
    return value.isdigit() and int(value) <= 2  # half-points: 1 pt or less is not meant to be read


def _wordml_text(xml: bytes) -> tuple[str, str]:
    """Visible and hidden text of a WordprocessingML part, in document order."""
    visible: list[str] = []
    hidden: list[str] = []
    run_hidden = False
    try:
        for event, element in iterparse(io.BytesIO(xml), events=("start", "end"), forbid_dtd=True):
            tag = element.tag
            if event == "start":
                if tag == f"{_W}r":
                    run_hidden = False
                continue
            target = hidden if run_hidden else visible
            if tag == f"{_W}rPr":
                run_hidden = _run_hidden(element)
            elif tag == f"{_W}t":
                target.append(element.text or "")
            elif tag == f"{_W}tab":
                target.append("\t")
            elif tag in (f"{_W}br", f"{_W}cr"):
                target.append("\n")
            elif tag == f"{_W}p":
                visible.append("\n")
                if hidden and hidden[-1] != "\n":
                    hidden.append("\n")
                element.clear()
    except DefusedXmlException as exc:
        raise ParseError("xml_forbidden", type(exc).__name__) from None
    except XMLParseError:
        raise ParseError("corrupt_xml") from None
    return "".join(visible), "".join(hidden)


def _core_properties(archive: zipfile.ZipFile, limits: ParseLimits) -> dict[str, str | None]:
    found: dict[str, str | None] = {"title": None, "author": None, "created": None}
    if "docProps/core.xml" not in archive.namelist():
        return found
    wanted = {f"{_DC}title": "title", f"{_DC}creator": "author", f"{_DCTERMS}created": "created"}
    try:
        for _, element in iterparse(
            io.BytesIO(_read_member(archive, "docProps/core.xml", limits)), forbid_dtd=True
        ):
            key = wanted.get(element.tag)
            if key is not None:
                found[key] = _short(element.text)
    except (DefusedXmlException, XMLParseError):
        return {"title": None, "author": None, "created": None}  # metadata is optional
    return found


def parse_docx(data: bytes, limits: ParseLimits) -> ParsedDocument:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError, NotImplementedError, EOFError):
        raise ParseError("corrupt_archive") from None
    with archive:
        vet_archive(archive, limits)
        names = set(archive.namelist())
        if "word/document.xml" not in names or "[Content_Types].xml" not in names:
            raise ParseError("not_docx", "missing word/document.xml")
        visible, hidden = _wordml_text(_read_member(archive, "word/document.xml", limits))
        for part in ("word/footnotes.xml", "word/endnotes.xml"):
            if part in names:
                extra_visible, extra_hidden = _wordml_text(_read_member(archive, part, limits))
                visible += "\n" + extra_visible
                hidden += extra_hidden
        properties = _core_properties(archive, limits)
    return ParsedDocument(
        kind="docx",
        text=visible.strip("\n"),
        title=properties["title"],
        author=properties["author"],
        created_at=properties["created"],
        hidden_text=hidden.strip(),
        metadata={"hidden_runs": bool(hidden.strip())},
    )


# ------------------------------------------------------------------------ text / markdown
def split_html_comments(text: str) -> tuple[str, list[str]]:
    """Linear-time removal of ``<!-- -->`` comments (invisible when Markdown is rendered)."""
    visible: list[str] = []
    comments: list[str] = []
    position = 0
    while True:
        start = text.find("<!--", position)
        end = text.find("-->", start + 4) if start >= 0 else -1
        if start < 0 or end < 0:  # an unterminated comment stays visible text
            visible.append(text[position:])
            return "".join(visible), comments
        visible.append(text[position:start])
        comments.append(text[start + 4 : end])
        position = end + 3


def parse_text(data: bytes, limits: ParseLimits) -> ParsedDocument:
    del limits
    return ParsedDocument(kind="text", text=_decode(data))


def parse_markdown(data: bytes, limits: ParseLimits) -> ParsedDocument:
    del limits
    text, comments = split_html_comments(_decode(data))
    title = None
    for line in text.splitlines()[:200]:
        if line.startswith("# "):
            title = _short(line[2:])
            break
    return ParsedDocument(
        kind="markdown",
        text=text,
        title=title,
        hidden_text="\n".join(comment.strip() for comment in comments[:1000]),
        metadata={"html_comments": len(comments)},
    )


# ------------------------------------------------------------------------------------ CSV
def _numeric(cell: str) -> bool:
    return cell.lstrip("+-").replace(".", "", 1).replace(",", "").isdigit()


def parse_csv(data: bytes, limits: ParseLimits) -> ParsedDocument:
    text = _decode(data)
    try:
        dialect: type[csv.Dialect] | csv.Dialect = csv.Sniffer().sniff(
            text[:16384], delimiters=",;\t|"
        )
    except csv.Error:
        dialect = csv.excel
    csv.field_size_limit(limits.max_csv_field_bytes)  # process-global: fine in the sandbox
    lines: list[str] = []
    header: list[str] | None = None
    rows = formula_like = size = 0
    warnings: list[str] = []
    try:
        for row in csv.reader(io.StringIO(text, newline=""), dialect):
            if len(row) > _MAX_COLUMNS:
                raise ParseError("csv_too_many_columns", str(len(row)))
            if header is None:
                header = [cell.strip()[:100] or f"column_{i + 1}" for i, cell in enumerate(row)]
                continue
            rows += 1
            if rows > limits.max_csv_rows:
                warnings.append("rows_truncated")
                break
            formula_like += sum(1 for c in row if c and c[0] in "=+-@" and not _numeric(c))
            line = "; ".join(
                f"{name}: {value}"
                for name, value in zip(header, row, strict=False)
                if value.strip()
            )
            lines.append(line)
            size += len(line) + 1
            if size > limits.max_text_chars:
                warnings.append("text_truncated")
                break
    except csv.Error as exc:
        raise ParseError("corrupt_csv", str(exc)[:120]) from None
    return ParsedDocument(
        kind="csv",
        text="\n".join(lines),
        metadata={
            "columns": header or [],
            "rows": rows,
            "delimiter": getattr(dialect, "delimiter", ","),
            # Cells starting with = + - @ execute as formulas if exported to a spreadsheet;
            # exporters must neutralise them (CSV injection).
            "formula_like_cells": formula_like,
        },
        warnings=warnings,
    )


# ----------------------------------------------------------------------------------- JSON
def json_depth(text: str, limit: int) -> int:
    """Maximum nesting depth, measured without recursion (stops counting past ``limit``)."""
    depth = deepest = 0
    for match in _BRACKETS.finditer(_JSON_STRING.sub('""', text)):
        if match.group() in "[{":
            depth += 1
            deepest = max(deepest, depth)
            if deepest > limit:
                return deepest
        else:
            depth -= 1
    return deepest


def _flatten(value: Any, limit: int) -> tuple[list[str], bool]:
    lines: list[str] = []
    stack: list[tuple[str, Any]] = [("", value)]
    size = 0
    while stack:
        path, node = stack.pop()
        if isinstance(node, dict):
            for key in reversed(list(node)):
                label = str(key)[:_MAX_KEY_IN_PATH]
                stack.append((f"{path}.{label}" if path else label, node[key]))
        elif isinstance(node, list):
            stack.extend((f"{path}[{index}]", node[index]) for index in reversed(range(len(node))))
        else:
            rendered = json.dumps(node, ensure_ascii=False)
            line = f"{path}: {rendered}" if path else rendered
            lines.append(line)
            size += len(line) + 1
            if size > limit:
                return lines, True
    return lines, False


def parse_json(data: bytes, limits: ParseLimits) -> ParsedDocument:
    text = _decode(data)
    depth = json_depth(text, limits.max_json_depth)
    if depth > limits.max_json_depth:
        raise ParseError("json_too_deep", f"depth > {limits.max_json_depth}")
    try:
        value = json.loads(text)
    except ValueError as exc:
        raise ParseError("corrupt_json", str(exc)[:120]) from None
    lines, truncated = _flatten(value, limits.max_text_chars)
    return ParsedDocument(
        kind="json",
        text="\n".join(lines),
        metadata={"depth": depth, "values": len(lines)},
        warnings=["text_truncated"] if truncated else [],
    )


# ----------------------------------------------------------------------------------- HTML
def parse_html(data: bytes, limits: ParseLimits) -> ParsedDocument:
    try:
        page = extract_html(_decode(data), max_chars=limits.max_text_chars)
    except HTMLTooComplex as exc:
        raise ParseError("too_complex", str(exc)[:120]) from None
    published = page.published_at.isoformat() if isinstance(page.published_at, datetime) else None
    return ParsedDocument(
        kind="html",
        text=page.text,
        title=_short(page.title),
        author=_short(page.author),
        created_at=published,
        language=_short(page.language, 35),
        hidden_text=page.hidden_text,
        invisible_characters=page.invisible_characters,
        metadata={"hidden_elements": page.hidden_elements, "links": len(page.links)},
    )


# ------------------------------------------------------------------------------- dispatch
_PARSERS: Final[dict[str, Callable[[bytes, ParseLimits], ParsedDocument]]] = {
    "pdf": parse_pdf,
    "docx": parse_docx,
    "text": parse_text,
    "markdown": parse_markdown,
    "csv": parse_csv,
    "json": parse_json,
    "html": parse_html,
}


def parse_document(kind: str, data: bytes, limits: ParseLimits) -> ParsedDocument:
    parser = _PARSERS.get(kind)
    if parser is None:
        raise ParseError("unsupported_kind", kind[:20])
    document = parser(data, limits)
    text = sanitize_text(document.text, max_chars=limits.max_text_chars)
    hidden = sanitize_text(document.hidden_text, max_chars=100_000)
    warnings = list(document.warnings)
    if len(text.text) >= limits.max_text_chars and "text_truncated" not in warnings:
        warnings.append("text_truncated")
    return document.model_copy(
        update={
            "text": text.text,
            "hidden_text": hidden.text,
            "invisible_characters": document.invisible_characters + text.suspicious_invisible,
            "warnings": warnings,
        }
    )
