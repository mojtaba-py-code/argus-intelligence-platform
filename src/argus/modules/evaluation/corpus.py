"""An in-memory web for evaluation runs: the dataset's pages, nothing else.

``CorpusNetwork`` is a DNS resolver and an httpcore network backend in one. It is plugged *under*
the real SSRF-guarded fetcher, so every egress check runs exactly as in production; only the
sockets are replaced. Every lookup and connection is recorded, which lets an evaluation prove
that an attacker's host was never resolved or contacted.

It exists for evaluation and is never part of a production container: the runner builds it
explicitly, per run.
"""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

import httpcore
from fpdf import FPDF

from argus.modules.evaluation.dataset import EvalCase, EvalPage
from argus.modules.sources.search import SearchResult
from argus.security.fetcher import FetchPolicy, SafeFetcher
from argus.security.ssrf import IPAddress, is_ip_literal

# Globally routable addresses (never contacted for real): the SSRF guard must accept them.
_ADDRESSES: Final = (
    "93.184.216.34",
    "151.101.1.69",
    "104.16.132.229",
    "185.199.108.153",
    "140.82.112.3",
    "13.107.21.200",
    "172.217.16.142",
    "23.215.0.136",
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
)


def _response(body: bytes, *, status: int = 200, media_type: str = "text/html") -> bytes:
    head = (
        f"HTTP/1.1 {status} OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n"
        f"Content-Type: {media_type}\r\n\r\n"
    )
    return head.encode("latin-1") + body


def render_page(page: EvalPage) -> tuple[bytes, str]:
    if page.format == "pdf":
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", size=11)
        pdf.set_title(page.title.encode("latin-1", "replace").decode("latin-1"))
        for paragraph in page.body.split("\n\n"):
            text = " ".join(paragraph.split()).encode("latin-1", "replace").decode("latin-1")
            pdf.multi_cell(0, 6, text, new_x="LMARGIN", new_y="NEXT")
        return bytes(pdf.output()), "application/pdf"
    head = (
        f"<meta property='article:published_time' content='{page.published.isoformat()}T00:00:00Z'>"
        if page.published
        else ""
    )
    html = (
        f"<!doctype html><html lang='en'><head><title>{page.title}</title>{head}</head>"
        f"<body><main><article>{page.body}</article></main></body></html>"
    )
    return html.encode("utf-8"), "text/html; charset=utf-8"


@dataclass(frozen=True)
class Contact:
    ip: str
    port: int


class _Stream(httpcore.AsyncNetworkStream):
    def __init__(self, network: CorpusNetwork, ip: str) -> None:
        self._network = network
        self._ip = ip
        self._sent = b""
        self._pending: bytearray | None = None

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        del timeout
        self._sent += buffer
        if self._pending is None and b"\r\n\r\n" in self._sent:
            request_line = self._sent.split(b"\r\n", 1)[0].decode("latin-1")
            path = request_line.split(" ")[1] if " " in request_line else "/"
            self._pending = bytearray(self._network.respond(self._ip, path.split("?", 1)[0]))

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        del timeout
        if not self._pending:
            return b""
        chunk = bytes(self._pending[:max_bytes])
        del self._pending[:max_bytes]
        return chunk

    async def aclose(self) -> None:
        return None

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del ssl_context, server_hostname, timeout
        return self

    def get_extra_info(self, info: str) -> object:
        return (self._ip, 443) if info == "server_addr" else None


class CorpusNetwork(httpcore.AsyncNetworkBackend):
    def __init__(self) -> None:
        self._hosts: dict[str, str] = {}
        self._pages: dict[tuple[str, str], bytes] = {}
        self.lookups: list[str] = []
        self.contacts: list[Contact] = []

    def load(self, case: EvalCase) -> None:
        """Serve this case's pages (pages of earlier cases stay reachable)."""
        for page in case.pages:
            ip = self._hosts.get(page.host)
            if ip is None:
                if len(self._hosts) >= len(_ADDRESSES):
                    msg = "too many distinct hosts in one evaluation run"
                    raise ValueError(msg)
                ip = self._hosts[page.host] = _ADDRESSES[len(self._hosts)]
            body, media_type = render_page(page)
            self._pages[(ip, page.path)] = _response(body, media_type=media_type)

    def respond(self, ip: str, path: str) -> bytes:
        return self._pages.get(
            (ip, path), _response(b"not found", status=404, media_type="text/plain")
        )

    def touched(self, host: str) -> bool:
        """Whether a host was ever looked up or (by address) contacted."""
        host = host.lower()
        ip = self._hosts.get(host)
        return host in self.lookups or (ip is not None and any(c.ip == ip for c in self.contacts))

    # ---------------------------------------------------- resolver + network backend
    async def resolve(self, host: str, port: int) -> list[IPAddress]:
        del port
        self.lookups.append(host.lower())
        ip = self._hosts.get(host.lower())
        address = is_ip_literal(ip) if ip else None
        if address is None:
            raise OSError(f"cannot resolve {host}")
        return [address]

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del timeout, local_address, socket_options
        self.contacts.append(Contact(host, port))
        if host not in self._hosts.values():
            raise httpcore.ConnectError(f"nothing listens on {host}")
        return _Stream(self, host)

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)

    def fetcher(self, policy: FetchPolicy) -> SafeFetcher:
        """The production fetcher (SSRF guard included) over this in-memory network."""
        return SafeFetcher(policy, resolver=self, inner_backend=self)


class CorpusSearch:
    """Search that returns the current case's listed URLs for every query."""

    name = "corpus"

    def __init__(self) -> None:
        self.results: list[str] = []
        self.queries: list[str] = []

    async def search(self, query: str, *, limit: int) -> list[SearchResult]:
        self.queries.append(query)
        return [
            SearchResult(url=url, title="", snippet="", rank=rank, provider=self.name)
            for rank, url in enumerate(self.results[:limit], start=1)
        ]

    async def aclose(self) -> None:
        return None
