"""SafeFetcher against hostile servers - all in memory, no sockets.

A scripted httpcore backend plays the role of the network. It records every address the
guarded backend actually *connects to*, which lets the tests prove the strongest property: a
blocked destination is never contacted at all.
"""

from __future__ import annotations

import asyncio
import gzip
from collections.abc import Iterable
from dataclasses import replace
from typing import Any

import httpcore
import pytest

from argus.security.egress import StaticResolver
from argus.security.fetcher import TEXT_TYPES, FetchError, FetchPolicy, SafeFetcher
from argus.security.ssrf import SafeURL

pytestmark = pytest.mark.security

PUBLIC_A = "93.184.216.34"
PUBLIC_B = "151.101.1.69"


def http_response(
    body: bytes = b"<html><body><p>Hello</p></body></html>",
    *,
    status: int = 200,
    headers: dict[str, str | None] | None = None,
    chunk: int | None = None,
) -> list[bytes]:
    merged: dict[str, str | None] = {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Length": str(len(body)),
        **(headers or {}),
    }
    head = {k: v for k, v in merged.items() if v is not None}  # None removes a default header
    lines = [f"HTTP/1.1 {status} X\r\n".encode()]
    lines += [f"{k}: {v}\r\n".encode() for k, v in head.items()]
    lines.append(b"\r\n")
    if chunk:
        lines += [body[i : i + chunk] for i in range(0, len(body), chunk)]
    else:
        lines.append(body)
    return lines


def redirect(location: str, status: int = 302) -> list[bytes]:
    return http_response(
        b"", status=status, headers={"Location": location, "Content-Type": "text/plain"}
    )


class SlowStream(httpcore.AsyncMockStream):
    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        await asyncio.sleep(0.5)
        return await super().read(max_bytes, timeout)


class ScriptedBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, responses: dict[str, list[bytes]], *, slow: bool = False) -> None:
        self.responses = responses
        self.connections: list[tuple[str, int]] = []
        self.slow = slow

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.connections.append((host, port))
        if host not in self.responses:
            raise httpcore.ConnectError(f"nothing listens on {host}")
        cls = SlowStream if self.slow else httpcore.AsyncMockStream
        return cls(list(self.responses[host]))

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


def fetcher(
    backend: ScriptedBackend,
    dns: dict[str, list[str]] | None = None,
    **policy: Any,
) -> SafeFetcher:
    resolver = StaticResolver(
        dns
        or {
            "site.example.com": [PUBLIC_A],
            "other.example.org": [PUBLIC_B],
            "rebind.example.net": ["10.0.0.5"],
            "mixed.example.net": [PUBLIC_A, "127.0.0.1"],
        }
    )
    base = FetchPolicy(user_agent="ArgusTest/1.0", total_timeout_s=5.0, max_bytes=64 * 1024)
    return SafeFetcher(replace(base, **policy), resolver=resolver, inner_backend=backend)


async def test_fetches_a_public_page_and_records_provenance() -> None:
    backend = ScriptedBackend({PUBLIC_A: http_response()})
    result = await fetcher(backend).fetch("https://site.example.com/article")
    assert result.status == 200
    assert result.media_type == "text/html"
    assert result.charset == "utf-8"
    assert "Hello" in result.text()
    assert result.url == "https://site.example.com/article"
    assert backend.connections == [(PUBLIC_A, 443)]  # connected to the validated IP


async def test_redirects_are_followed_and_revalidated() -> None:
    backend = ScriptedBackend(
        {
            PUBLIC_A: redirect("https://other.example.org/final"),
            PUBLIC_B: http_response(b"<p>final</p>"),
        }
    )
    result = await fetcher(backend).fetch("https://site.example.com/start")
    assert result.url == "https://other.example.org/final"
    assert result.redirects == ["https://site.example.com/start"]


@pytest.mark.parametrize(
    "location",
    [
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "https://rebind.example.net/",
        "https://mixed.example.net/",
        "http://[::1]/",
        "file:///etc/passwd",
        "https://site.example.com:8443/",
        "http://0x7f.1/",
    ],
)
async def test_redirects_into_private_space_are_blocked_before_connecting(location: str) -> None:
    backend = ScriptedBackend({PUBLIC_A: redirect(location)})
    with pytest.raises(FetchError) as caught:
        await fetcher(backend).fetch("https://site.example.com/")
    assert caught.value.code == "blocked"
    connected = {host for host, _ in backend.connections}
    assert connected == {PUBLIC_A}  # the private target was never contacted


@pytest.mark.parametrize("url", ["https://rebind.example.net/", "https://mixed.example.net/"])
async def test_dns_answers_are_validated_before_connecting(url: str) -> None:
    backend = ScriptedBackend({})
    with pytest.raises(FetchError, match="blocked"):
        await fetcher(backend).fetch(url)
    assert backend.connections == []


async def test_https_to_http_downgrade_is_refused() -> None:
    backend = ScriptedBackend({PUBLIC_A: redirect("http://other.example.org/")})
    with pytest.raises(FetchError, match="insecure_redirect"):
        await fetcher(backend).fetch("https://site.example.com/")


async def test_redirect_loops_and_excessive_hops() -> None:
    loop = ScriptedBackend({PUBLIC_A: redirect("https://site.example.com/")})
    with pytest.raises(FetchError, match="redirect_loop"):
        await fetcher(loop).fetch("https://site.example.com/")
    hops = ScriptedBackend(
        {
            PUBLIC_A: redirect("https://other.example.org/x"),
            PUBLIC_B: redirect("https://site.example.com/y"),
        }
    )
    with pytest.raises(FetchError, match="redirect"):
        await fetcher(hops, max_redirects=1).fetch("https://site.example.com/")


async def test_declared_size_over_the_limit_is_refused_without_reading() -> None:
    backend = ScriptedBackend(
        {PUBLIC_A: http_response(b"x", headers={"Content-Length": str(10**9)})}
    )
    with pytest.raises(FetchError, match="too_large"):
        await fetcher(backend).fetch("https://site.example.com/")


async def test_streamed_body_over_the_limit_is_refused() -> None:
    body = b"<p>" + b"a" * 200_000 + b"</p>"
    backend = ScriptedBackend(
        {
            PUBLIC_A: http_response(
                body, headers={"Content-Length": None, "Transfer-Encoding": "chunked"}, chunk=None
            )
        }
    )
    backend.responses[PUBLIC_A] = [
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n",
        *[body[i : i + 8192] for i in range(0, len(body), 8192)],
    ]
    with pytest.raises(FetchError, match="too_large"):
        await fetcher(backend, max_bytes=64 * 1024).fetch("https://site.example.com/")


async def test_gzip_bomb_is_stopped_while_inflating() -> None:
    bomb = gzip.compress(b"\x00" * (50 * 1024 * 1024), compresslevel=9)
    assert len(bomb) < 100 * 1024
    backend = ScriptedBackend(
        {
            PUBLIC_A: http_response(
                bomb, headers={"Content-Encoding": "gzip", "Content-Type": "text/plain"}, chunk=4096
            )
        }
    )
    with pytest.raises(FetchError) as caught:
        await fetcher(backend, max_bytes=1024 * 1024).fetch("https://site.example.com/")
    assert caught.value.code in {"too_large", "decompression_bomb"}


async def test_gzip_content_is_decoded() -> None:
    page = b"<html><body><p>compressed page</p></body></html>"
    backend = ScriptedBackend(
        {PUBLIC_A: http_response(gzip.compress(page), headers={"Content-Encoding": "gzip"})}
    )
    result = await fetcher(backend).fetch("https://site.example.com/")
    assert result.content == page


@pytest.mark.parametrize(
    ("content_type", "body", "code"),
    [
        ("application/octet-stream", b"\x00\x01binary", "content_type"),
        ("image/png", b"\x89PNG\r\n\x1a\n....", "content_type"),
        ("text/html", b"MZ\x90\x00 disguised executable", "content_mismatch"),
        ("text/plain", b"PK\x03\x04 zip pretending to be text", "content_mismatch"),
    ],
)
async def test_dangerous_content_is_refused(content_type: str, body: bytes, code: str) -> None:
    backend = ScriptedBackend(
        {PUBLIC_A: http_response(body, headers={"Content-Type": content_type})}
    )
    with pytest.raises(FetchError) as caught:
        await fetcher(backend).fetch("https://site.example.com/")
    assert caught.value.code == code


async def test_unsupported_encodings_are_refused() -> None:
    backend = ScriptedBackend(
        {PUBLIC_A: http_response(b"....", headers={"Content-Encoding": "br"})}
    )
    with pytest.raises(FetchError, match="unsupported_encoding"):
        await fetcher(backend).fetch("https://site.example.com/")


async def test_http_errors_are_reported() -> None:
    backend = ScriptedBackend(
        {PUBLIC_A: http_response(b"nope", status=404, headers={"Content-Type": "text/plain"})}
    )
    with pytest.raises(FetchError, match="http_error"):
        await fetcher(backend).fetch("https://site.example.com/")


async def test_overall_deadline_stops_slow_servers() -> None:
    backend = ScriptedBackend({PUBLIC_A: http_response(b"<p>x</p>" * 50, chunk=10)}, slow=True)
    with pytest.raises(FetchError, match="timeout"):
        await fetcher(backend, total_timeout_s=1.0).fetch("https://site.example.com/")


async def test_gate_runs_on_every_hop_and_can_refuse() -> None:
    seen: list[str] = []

    async def gate(url: SafeURL) -> None:
        seen.append(str(url))
        if url.host == "other.example.org":
            raise FetchError("robots_disallowed", str(url))

    backend = ScriptedBackend({PUBLIC_A: redirect("https://other.example.org/private")})
    with pytest.raises(FetchError, match="robots_disallowed"):
        await fetcher(backend).fetch("https://site.example.com/", gate=gate)
    assert seen == ["https://site.example.com/", "https://other.example.org/private"]
    assert {h for h, _ in backend.connections} == {PUBLIC_A}


async def test_pdf_is_accepted_only_when_asked_for() -> None:
    backend = ScriptedBackend(
        {PUBLIC_A: http_response(b"%PDF-1.7 ...", headers={"Content-Type": "application/pdf"})}
    )
    with pytest.raises(FetchError, match="content_type"):
        await fetcher(backend).fetch("https://site.example.com/report.pdf")
    result = await fetcher(backend).fetch(
        "https://site.example.com/report.pdf", accept=TEXT_TYPES | {"application/pdf"}
    )
    assert result.media_type == "application/pdf"
