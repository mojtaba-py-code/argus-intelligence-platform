"""An in-memory internet for tests (importable as ``tests.fake_network``).

``FakeInternet`` is both the DNS (a resolver over a mutable table) and the network (an httpcore
backend serving scripted responses per *(IP, path)*). It is plugged *under* the real
``GuardedNetworkBackend``, so every SSRF check still runs exactly as in production; the fake
only replaces the sockets. Every connection and every request is recorded, which lets a test
prove the strongest egress property: a blocked destination was never contacted at all.
"""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import Any

import httpcore

from argus.security.fetcher import FetchPolicy, SafeFetcher
from argus.security.ssrf import IPAddress, is_ip_literal

Response = list[bytes]

PUBLIC_A = "93.184.216.34"
PUBLIC_B = "151.101.1.69"
PUBLIC_C = "104.16.132.229"
PUBLIC_D = "185.199.108.153"


def http_response(
    body: bytes | str = b"<html><body><p>Hello</p></body></html>",
    *,
    status: int = 200,
    content_type: str | None = "text/html; charset=utf-8",
    headers: dict[str, str] | None = None,
) -> Response:
    """A complete HTTP/1.1 response. ``Connection: close`` keeps one request per connection."""
    data = body.encode("utf-8") if isinstance(body, str) else body
    head = {"Content-Length": str(len(data)), "Connection": "close"}
    if content_type is not None:
        head["Content-Type"] = content_type
    head.update(headers or {})
    lines = [f"HTTP/1.1 {status} Scripted\r\n".encode()]
    lines += [f"{name}: {value}\r\n".encode() for name, value in head.items()]
    return [b"".join(lines) + b"\r\n" + data]


def redirect(location: str, status: int = 302) -> Response:
    return http_response(
        b"", status=status, content_type="text/plain", headers={"Location": location}
    )


def html_page(title: str, body: str, *, head: str = "") -> str:
    return (
        f"<!doctype html><html lang='en'><head><title>{title}</title>{head}</head>"
        f"<body><main>{body}</main></body></html>"
    )


@dataclass(frozen=True)
class Request:
    ip: str
    port: int
    method: str
    path: str
    host: str
    header_names: frozenset[str] = frozenset()


class _Stream(httpcore.AsyncNetworkStream):
    def __init__(self, internet: FakeInternet, ip: str, port: int) -> None:
        self._internet = internet
        self._ip = ip
        self._port = port
        self._sent = b""
        self._pending: bytearray | None = None

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        del timeout
        self._sent += buffer
        if self._pending is None and b"\r\n\r\n" in self._sent:
            lines = self._sent.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ", 2)
            host = next(
                (
                    line.split(":", 1)[1].strip()
                    for line in lines[1:]
                    if line.lower().startswith("host:")
                ),
                "",
            )
            names = frozenset(
                line.split(":", 1)[0].strip().lower() for line in lines[1:] if ":" in line
            )
            request = Request(self._ip, self._port, method, target, host, names)
            self._internet.requests.append(request)
            self._pending = bytearray(b"".join(self._internet.respond(request)))

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        del timeout
        if self._internet.latency_s:
            internet = self._internet
            internet.waiting += 1
            internet.peak_waiting = max(internet.peak_waiting, internet.waiting)
            try:
                await asyncio.sleep(internet.latency_s)
            finally:
                internet.waiting -= 1
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
        return (self._ip, self._port) if info == "server_addr" else None


class FakeInternet(httpcore.AsyncNetworkBackend):
    def __init__(self) -> None:
        self.dns: dict[str, list[str]] = {}
        self.pages: dict[tuple[str, str], Response] = {}
        self.listening: set[str] = set()
        self.connections: list[tuple[str, int]] = []
        self.requests: list[Request] = []
        self.latency_s = 0.0
        self.waiting = 0
        self.peak_waiting = 0
        """Most responses awaited at the same moment (with ``latency_s``): measured concurrency."""

    # ----------------------------------------------------------------- scripting
    def host(self, name: str, *addresses: str) -> None:
        """A DNS record only (e.g. a rebinding name that points into private space)."""
        self.dns[name.lower()] = list(addresses)

    def site(
        self,
        name: str,
        ip: str,
        pages: dict[str, Response | str] | None = None,
        *,
        robots: Response | str | None = None,
    ) -> None:
        self.host(name, ip)
        self.listening.add(ip)
        for path, response in (pages or {}).items():
            self.page(ip, path, response)
        if robots is not None:
            self.page(
                ip,
                "/robots.txt",
                robots
                if isinstance(robots, list)
                else http_response(robots, content_type="text/plain"),
            )

    def page(self, ip: str, path: str, response: Response | str) -> None:
        self.pages[(ip, path)] = response if isinstance(response, list) else http_response(response)

    def respond(self, request: Request) -> Response:
        return self.pages.get(
            (request.ip, request.path),
            http_response(b"not found", status=404, content_type="text/plain"),
        )

    # --------------------------------------------------------------- inspection
    def contacted(self, ip: str) -> bool:
        return any(host == ip for host, _ in self.connections)

    def paths(self, ip: str | None = None) -> list[str]:
        return [r.path for r in self.requests if ip is None or r.ip == ip]

    # ------------------------------------------------- resolver + network backend
    async def resolve(self, host: str, port: int) -> list[IPAddress]:
        del port
        addresses = [a for a in (is_ip_literal(raw) for raw in self.dns.get(host.lower(), [])) if a]
        if not addresses:
            raise OSError(f"cannot resolve {host}")
        return addresses

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del timeout, local_address, socket_options
        self.connections.append((host, port))
        if host not in self.listening:
            raise httpcore.ConnectError(f"nothing listens on {host}")
        return _Stream(self, host, port)

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)

    def fetcher(self, **policy: Any) -> SafeFetcher:
        """A real SafeFetcher (SSRF guard included) whose sockets are this fake."""
        base = FetchPolicy(user_agent="ArgusTest/1.0 (+https://example.com/bot)")
        return SafeFetcher(replace(base, **policy), resolver=self, inner_backend=self)
