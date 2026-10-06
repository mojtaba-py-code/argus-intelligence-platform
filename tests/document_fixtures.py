"""Builders for document fixtures (importable as ``tests.document_fixtures``).

Fixtures are generated at test time instead of being committed as binary files: they stay
reviewable, and hostile ones (zip bombs, XXE, the antivirus test file) never sit on disk where a
local antivirus or a careless double-click could meet them.
"""

from __future__ import annotations

import asyncio
import io
import zipfile
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from fpdf import FPDF
from fpdf.actions import LaunchAction
from fpdf.enums import EncryptionMethod

# The industry-standard antivirus *test* file, stored reversed so no scanner flags this source.
_EICAR_REVERSED = r"*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\4[PA@%P!O5X"
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def eicar() -> bytes:
    return _EICAR_REVERSED[::-1].encode("ascii")


def make_pdf(
    pages: Iterable[str] = ("Revenue grew 42 percent in 2026.",),
    *,
    title: str | None = "Market report",
    author: str | None = "Jane Analyst",
    user_password: str | None = None,
    owner_password: str | None = None,
    launch: bool = False,
) -> bytes:
    pdf = FPDF()
    if title:
        pdf.set_title(title)
    if author:
        pdf.set_author(author)
    for text in pages:
        pdf.add_page()
        pdf.set_font("helvetica", size=12)
        pdf.multi_cell(0, 8, text)
    if launch:
        pdf.add_action(LaunchAction("calc.exe"), x=10, y=10, w=50, h=10)
    if owner_password or user_password:
        pdf.set_encryption(
            owner_password=owner_password or "owner-secret",
            user_password=user_password,
            encryption_method=EncryptionMethod.AES_256,
        )
    return bytes(pdf.output())


def _paragraph(text: str, *, hidden: bool = False, tiny: bool = False) -> str:
    properties = ""
    if hidden:
        properties = "<w:rPr><w:vanish/></w:rPr>"
    elif tiny:
        properties = '<w:rPr><w:sz w:val="1"/></w:rPr>'
    return f"<w:p><w:r>{properties}<w:t xml:space='preserve'>{text}</w:t></w:r></w:p>"


def docx_xml(body: str, *, doctype: str = "") -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>{doctype}'
        f'<w:document xmlns:w="{W_NS}"><w:body>{body}</w:body></w:document>'
    ).encode()


def make_zip(entries: dict[str, bytes], *, compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def make_docx(
    paragraphs: Iterable[str] = ("First paragraph.", "Second paragraph."),
    *,
    hidden: Iterable[str] = (),
    tiny: Iterable[str] = (),
    title: str | None = "Board memo",
    author: str | None = "Ali Rezaei",
    document_xml: bytes | None = None,
    extra: dict[str, bytes] | None = None,
) -> bytes:
    body = "".join(_paragraph(p) for p in paragraphs)
    body += "".join(_paragraph(p, hidden=True) for p in hidden)
    body += "".join(_paragraph(p, tiny=True) for p in tiny)
    core = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
        f"<dc:title>{title or ''}</dc:title><dc:creator>{author or ''}</dc:creator>"
        "<dcterms:created>2026-09-30T08:00:00Z</dcterms:created></cp:coreProperties>"
    ).encode()
    entries = {
        "[Content_Types].xml": b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        "word/document.xml": document_xml if document_xml is not None else docx_xml(body),
        "docProps/core.xml": core,
        **(extra or {}),
    }
    return make_zip(entries)


@dataclass
class FakeClamd:
    """A minimal clamd speaking INSTREAM/PING over TCP, for scanner adapter tests."""

    infected_marker: bytes = b"MALWARE-MARKER"
    reply_override: bytes | None = None
    received: list[bytes] = field(default_factory=list)
    port: int = 0

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        command = await reader.readuntil(b"\x00")
        if command == b"zPING\x00":
            writer.write(b"PONG\x00")
        else:
            data = bytearray()
            while True:
                size = int.from_bytes(await reader.readexactly(4), "big")
                if size == 0:
                    break
                data += await reader.readexactly(size)
            self.received.append(bytes(data))
            if self.reply_override is not None:
                writer.write(self.reply_override)
            elif self.infected_marker in data:
                writer.write(b"stream: Test.Malware FOUND\x00")
            else:
                writer.write(b"stream: OK\x00")
        await writer.drain()
        writer.close()

    @asynccontextmanager
    async def running(self) -> AsyncIterator[FakeClamd]:
        server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = server.sockets[0].getsockname()[1]
        try:
            yield self
        finally:
            server.close()
            await server.wait_closed()
