"""Content-type detection from magic bytes. Declared types (HTTP headers, file extensions, upload
MIME types) are claims; the bytes are evidence. Executables and archives disguised as documents are
rejected wherever content enters the platform."""

from __future__ import annotations

import json
from typing import Final

KIND_PDF: Final = "application/pdf"
KIND_ZIP: Final = "application/zip"
KIND_DOCX: Final = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
KIND_HTML: Final = "text/html"
KIND_JSON: Final = "application/json"
KIND_TEXT: Final = "text/plain"
KIND_EXECUTABLE: Final = "application/x-executable"
KIND_BINARY: Final = "application/octet-stream"

_SIGNATURES: Final[tuple[tuple[bytes, str], ...]] = (
    (b"%PDF-", KIND_PDF),
    (b"PK\x03\x04", KIND_ZIP),
    (b"MZ", KIND_EXECUTABLE),
    (b"\x7fELF", KIND_EXECUTABLE),
    (b"\xfe\xed\xfa\xce", KIND_EXECUTABLE),
    (b"\xfe\xed\xfa\xcf", KIND_EXECUTABLE),
    (b"\xcf\xfa\xed\xfe", KIND_EXECUTABLE),
    (b"\xca\xfe\xba\xbe", KIND_EXECUTABLE),
    (b"#!", KIND_EXECUTABLE),
    (b"\x1f\x8b", "application/gzip"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF8", "image/gif"),
    (b"Rar!", "application/x-rar"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),
)
_HTML_MARKERS: Final = (b"<!doctype html", b"<html", b"<head", b"<body", b"<title", b"<meta")
DANGEROUS: Final = frozenset(
    {
        KIND_EXECUTABLE,
        "application/x-rar",
        "application/x-7z-compressed",
        "application/x-ole-storage",
    }
)


def sniff(data: bytes) -> str:
    """Best-effort media type from the first bytes."""
    head = data[:4096]
    for signature, kind in _SIGNATURES:
        if head.startswith(signature):
            return kind
    stripped = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if any(marker in stripped[:1024] for marker in _HTML_MARKERS):
        return KIND_HTML
    if stripped[:1] in (b"{", b"["):
        try:
            json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            pass
        else:
            return KIND_JSON
    if _looks_textual(head):
        return KIND_TEXT
    return KIND_BINARY


def _looks_textual(data: bytes) -> bool:
    if not data:
        return True
    if b"\x00" in data:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data[:-3].decode("utf-8")  # a multi-byte sequence may be cut at the boundary
        except UnicodeDecodeError:
            return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return printable / max(1, len(text)) > 0.95


def compatible(declared: str, sniffed: str) -> bool:
    """Is the declared media type a plausible description of the sniffed bytes?"""
    if sniffed in DANGEROUS:
        return False
    if declared == sniffed:
        return True
    textual = {KIND_TEXT, KIND_HTML, KIND_JSON}
    text_declared = declared.startswith("text/") or declared in {
        "application/json",
        "application/xml",
        "application/xhtml+xml",
        "application/ld+json",
        "application/rss+xml",
        "application/atom+xml",
    }
    if text_declared:
        return sniffed in textual
    if declared == KIND_DOCX:
        return sniffed == KIND_ZIP
    return False
