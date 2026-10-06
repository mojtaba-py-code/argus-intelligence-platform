"""Upload validation: which kind of document is this, *really*?

The bytes decide (magic-byte sniffing); the file extension and the declared MIME type are claims
that must agree with them. Executables and archives are refused whatever they are called. Runs in
the API process before anything is stored, so it only reads headers and the ZIP central directory
- the actual parsing happens later, in the sandbox.
"""

from __future__ import annotations

import io
import unicodedata
import zipfile
from dataclasses import dataclass
from typing import Final
from urllib.parse import quote

from argus.core.errors import UnsupportedMediaType
from argus.security.content import (
    DANGEROUS,
    KIND_DOCX,
    KIND_HTML,
    KIND_JSON,
    KIND_PDF,
    KIND_TEXT,
    KIND_ZIP,
    sniff,
)
from argus.security.text import sanitize_text


class UnsupportedDocument(UnsupportedMediaType):
    code = "unsupported_document"
    title = "Unsupported document"

    def __init__(self, detail: str, *, reason: str) -> None:
        super().__init__(detail, extensions={"reason": reason})
        self.reason = reason


@dataclass(frozen=True)
class _Rule:
    extensions: frozenset[str]
    mime_types: frozenset[str]
    sniffed: frozenset[str]
    media_type: str


_TEXTUAL: Final = frozenset({KIND_TEXT, KIND_HTML, KIND_JSON})
_RULES: Final[dict[str, _Rule]] = {
    "pdf": _Rule(
        frozenset({".pdf"}), frozenset({"application/pdf"}), frozenset({KIND_PDF}), KIND_PDF
    ),
    "docx": _Rule(frozenset({".docx"}), frozenset({KIND_DOCX}), frozenset({KIND_ZIP}), KIND_DOCX),
    "text": _Rule(
        frozenset({".txt", ".text", ".log"}), frozenset({"text/plain"}), _TEXTUAL, "text/plain"
    ),
    "markdown": _Rule(
        frozenset({".md", ".markdown"}),
        frozenset({"text/markdown", "text/x-markdown", "text/plain"}),
        _TEXTUAL,
        "text/markdown",
    ),
    "csv": _Rule(
        frozenset({".csv", ".tsv"}),
        frozenset({"text/csv", "text/tab-separated-values", "application/csv", "text/plain"}),
        frozenset({KIND_TEXT}),
        "text/csv",
    ),
    "json": _Rule(
        frozenset({".json"}),
        frozenset({"application/json", "text/json"}),
        frozenset({KIND_JSON}),
        "application/json",
    ),
    "html": _Rule(
        frozenset({".html", ".htm"}),
        frozenset({"text/html", "application/xhtml+xml"}),
        frozenset({KIND_HTML, KIND_TEXT}),
        "text/html",
    ),
}
_GENERIC_MIME: Final = frozenset({"", "application/octet-stream", "binary/octet-stream"})
_FORBIDDEN_IN_NAMES: Final = frozenset('<>:"/\\|?*')
SUPPORTED_EXTENSIONS: Final = sorted(ext for rule in _RULES.values() for ext in rule.extensions)


def clean_filename(raw: str | None) -> str:
    """A safe display name: last path segment, NFC, no controls/bidi tricks, bounded."""
    name = (raw or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = sanitize_text(unicodedata.normalize("NFC", name)).text
    name = "".join(ch for ch in name if ch.isprintable() and ch not in _FORBIDDEN_IN_NAMES)
    name = " ".join(name.split()).strip(" .")
    if len(name) > 200:
        stem, dot, extension = name.rpartition(".")
        name = (stem[: 190 - len(extension)] + dot + extension) if dot else name[:200]
    return name or "document"


def extension_of(filename: str) -> str:
    _, dot, extension = filename.rpartition(".")
    return f".{extension.lower()}" if dot else ""


def _is_docx(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()  # central directory only - nothing is decompressed
    except (zipfile.BadZipFile, ValueError, OSError, NotImplementedError, EOFError):
        return False
    return "word/document.xml" in names and "[Content_Types].xml" in names


def decide_kind(filename: str, declared_type: str | None, data: bytes) -> tuple[str, str]:
    """Return ``(kind, media_type)`` or raise :class:`UnsupportedDocument`."""
    if not data:
        raise UnsupportedDocument("The file is empty.", reason="empty")
    extension = extension_of(filename)
    kind = next((k for k, rule in _RULES.items() if extension in rule.extensions), None)
    if kind is None:
        supported = ", ".join(SUPPORTED_EXTENSIONS)
        raise UnsupportedDocument(
            f"Files of this type are not accepted. Supported: {supported}.", reason="extension"
        )
    rule = _RULES[kind]
    sniffed = sniff(data)
    if sniffed in DANGEROUS:
        raise UnsupportedDocument(
            "The file content is an executable or archive.", reason="dangerous_content"
        )
    if sniffed not in rule.sniffed or (kind == "docx" and not _is_docx(data)):
        raise UnsupportedDocument(
            f"The file content does not match its {extension} extension.", reason="content_mismatch"
        )
    declared = (declared_type or "").split(";", 1)[0].strip().lower()
    if declared not in _GENERIC_MIME and declared not in rule.mime_types:
        raise UnsupportedDocument(
            "The declared content type does not match the file.", reason="mime_mismatch"
        )
    return kind, rule.media_type


def content_disposition(filename: str) -> str:
    """RFC 6266 attachment header with an ASCII fallback and an RFC 5987 UTF-8 name."""
    fallback = "".join(
        ch if (ch.isascii() and ch.isalnum()) or ch in "._- " else "_" for ch in filename
    )
    return f"attachment; filename=\"{fallback or 'document'}\"; filename*=UTF-8''{quote(filename, safe='')}"
