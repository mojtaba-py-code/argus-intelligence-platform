"""DNS-pinning network backend for httpcore (ADR 0008).

``GuardedNetworkBackend.connect_tcp`` is the single choke point for every outbound connection the
fetcher makes - first requests, redirects and keep-alive reconnects alike. It:

1. re-checks the host name (literal IPs included);
2. resolves it **once** and rejects the connection if *any* answer is non-public (an attacker's DNS
   cannot mix a public and a private address and hope the client picks the private one);
3. connects to the **validated IP**, not to the name. TLS still verifies the original host name,
   because httpcore passes it separately as the SNI / certificate name. A second resolution
   (DNS rebinding) therefore never happens.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Iterable
from typing import Protocol

import httpcore

from argus.core.logging import get_logger
from argus.infrastructure.observability.metrics import Metrics
from argus.security.ssrf import (
    EgressBlocked,
    IPAddress,
    blocked_reason,
    hostname_blocked_reason,
    is_ip_literal,
    normalise_hostname,
)

log = get_logger(__name__)


class Resolver(Protocol):
    async def resolve(self, host: str, port: int) -> list[IPAddress]: ...


class SystemResolver:
    def __init__(self, timeout_s: float = 5.0) -> None:
        self._timeout_s = timeout_s

    async def resolve(self, host: str, port: int) -> list[IPAddress]:
        loop = asyncio.get_running_loop()
        async with asyncio.timeout(self._timeout_s):
            infos = await loop.getaddrinfo(
                host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
            )
        addresses: list[IPAddress] = []
        for *_, sockaddr in infos:
            address = is_ip_literal(str(sockaddr[0]).split("%", 1)[0])
            if address is not None and address not in addresses:
                addresses.append(address)
        return addresses


class StaticResolver:
    """Deterministic resolver for tests and air-gapped demos."""

    def __init__(self, table: dict[str, list[str]]) -> None:
        self._table = {host.lower(): list(addrs) for host, addrs in table.items()}

    async def resolve(self, host: str, port: int) -> list[IPAddress]:
        del port
        result = []
        for raw in self._table.get(host.lower(), []):
            address = is_ip_literal(raw)
            if address is not None:
                result.append(address)
        if not result:
            raise OSError(f"cannot resolve {host}")
        return result


class GuardedNetworkBackend(httpcore.AsyncNetworkBackend):
    def __init__(
        self,
        resolver: Resolver,
        inner: httpcore.AsyncNetworkBackend | None = None,
        *,
        allowed_ports: tuple[int, ...] = (80, 443),
        metrics: Metrics | None = None,
    ) -> None:
        self._resolver = resolver
        self._inner = inner or httpcore.AnyIOBackend()
        self._allowed_ports = allowed_ports
        self._metrics = metrics

    def _block(self, reason: str, host: str) -> EgressBlocked:
        if self._metrics is not None:
            self._metrics.egress_blocked.labels(reason.split(":", 1)[0]).inc()
        log.warning("egress.blocked", reason=reason, host=host[:255])
        return EgressBlocked(reason)

    async def _validated_addresses(self, host: str, port: int) -> list[IPAddress]:
        if port not in self._allowed_ports:
            raise self._block("port_not_allowed", host)
        literal = is_ip_literal(host)
        if literal is not None:
            reason = blocked_reason(literal)
            if reason is not None:
                raise self._block(reason, host)
            return [literal]
        name = normalise_hostname(host)
        reason = hostname_blocked_reason(name)
        if reason is not None:
            raise self._block(reason, host)
        try:
            addresses = await self._resolver.resolve(name, port)
        except (OSError, TimeoutError) as exc:
            raise httpcore.ConnectError(f"DNS resolution failed for {name}") from exc
        if not addresses:
            raise httpcore.ConnectError(f"no addresses for {name}")
        for address in addresses:
            reason = blocked_reason(address)
            if reason is not None:
                raise self._block(f"resolved_{reason}", host)
        return addresses

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 - httpcore's backend interface
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        addresses = await self._validated_addresses(host, port)
        last_error: Exception | None = None
        for address in addresses:
            try:
                return await self._inner.connect_tcp(
                    str(address),
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout, OSError) as exc:
                last_error = exc
        raise httpcore.ConnectError(f"could not connect to {host}") from last_error

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109 - httpcore's backend interface
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del timeout, socket_options
        raise self._block("unix_socket", path)

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)
