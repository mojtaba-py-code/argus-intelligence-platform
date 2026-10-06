"""SSRF validation primitives (pure functions, no I/O). See ADR 0008.

Three questions are answered separately and *all* must pass:

1. Is the URL acceptable? (http/https only, no credentials, sane length, allowed port, valid host)
2. Is the host name acceptable? (no ``localhost``, ``*.internal``, single-label names, ...)
3. Is every resolved / literal **IP address** public? (RFC 1918, loopback, link-local - which
   includes the cloud metadata address 169.254.169.254 - CGNAT, ULA, multicast, documentation and
   reserved ranges, and IPv6 transition forms that smuggle an IPv4 address inside.)

IPv4 literals are parsed the way ``inet_aton`` and browsers do, so ``http://2130706433``,
``http://0x7f.1`` and ``http://0177.0.0.1`` are all recognised as 127.0.0.1 - checking only
dotted-quad strings is the classic SSRF filter bypass.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Final
from urllib.parse import urlsplit, urlunsplit

import idna

from argus.core.errors import PolicyViolation

MAX_URL_LENGTH: Final = 2048
type IPAddress = IPv4Address | IPv6Address


class EgressBlocked(PolicyViolation):
    code = "egress_blocked"
    title = "Destination not allowed"
    default_detail = "The destination is not allowed."

    def __init__(self, reason: str) -> None:
        super().__init__(log_context={"reason": reason})
        self.reason = reason


_BLOCKED_V4: Final = tuple(
    IPv4Network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)
_BLOCKED_V6: Final = tuple(
    IPv6Network(n)
    for n in (
        "::/128",
        "::1/128",
        "::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
        "5f00::/16",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
    )
)
_NAT64: Final = IPv6Network("64:ff9b::/96")
_MAPPED: Final = IPv6Network("::ffff:0:0/96")

_BLOCKED_SUFFIXES: Final = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".intranet",
    ".lan",
    ".corp",
    ".home",
    ".home.arpa",
    ".private",
    ".arpa",
    ".onion",
    ".test",
    ".invalid",
    ".example",
)
_BLOCKED_NAMES: Final = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata",
        "instance-data",
        "kubernetes",
        "kubernetes.default",
        "metadata.google.internal",
    }
)
_LABEL: Final = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_NUMERIC_PART: Final = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class SafeURL:
    """A validated, normalised URL. ``host`` is the ASCII (IDNA) form or an IP literal."""

    scheme: str
    host: str
    port: int
    path_and_query: str
    ip_literal: IPAddress | None

    @property
    def origin(self) -> str:
        default = 443 if self.scheme == "https" else 80
        host = f"[{self.host}]" if isinstance(self.ip_literal, IPv6Address) else self.host
        return f"{self.scheme}://{host}" + ("" if self.port == default else f":{self.port}")

    def __str__(self) -> str:
        return self.origin + self.path_and_query


# ------------------------------------------------------------------------------- IPs
def _parse_part(part: str) -> int | None:
    if not part or not _NUMERIC_PART.fullmatch(part):
        return None
    lowered = part.lower()
    if lowered.startswith("0x"):
        return int(lowered[2:] or "0", 16)
    if len(part) > 1 and part.startswith("0"):
        return int(part, 8) if all(ch in "01234567" for ch in part) else None
    return int(part, 10)


def parse_ipv4_literal(host: str) -> IPv4Address | None:
    """inet_aton semantics: 1-4 parts, each decimal/octal/hex; the last part fills the rest."""
    parts = host.split(".")
    if host.endswith(".") and len(parts) > 1:
        parts = parts[:-1]
    if not 1 <= len(parts) <= 4:
        return None
    values = [_parse_part(p) for p in parts]
    if any(v is None for v in values):
        return None
    numbers = [v for v in values if v is not None]
    *head, last = numbers
    if any(v > 255 for v in head):
        return None
    remaining_bits = 8 * (4 - len(head))
    if last >= 1 << remaining_bits:
        return None
    value = 0
    for v in head:
        value = (value << 8) | v
    value = (value << remaining_bits) | last
    return IPv4Address(value)


def blocked_reason(ip: IPAddress) -> str | None:
    """``None`` when the address is public; otherwise a short reason code."""
    if isinstance(ip, IPv6Address):
        if ip in _MAPPED or ip.ipv4_mapped is not None:
            return "ipv4_mapped"
        if ip in _NAT64:
            embedded = IPv4Address(int(ip) & 0xFFFFFFFF)
            inner = blocked_reason(embedded)
            return f"nat64_{inner}" if inner else None
        if ip.sixtofour is not None:
            return "6to4"
        if ip.teredo is not None:
            return "teredo"
        for network in _BLOCKED_V6:
            if ip in network:
                return f"reserved_v6:{network}"
        if not ip.is_global:
            return "non_global_v6"
        return None
    for network4 in _BLOCKED_V4:
        if ip in network4:
            return f"reserved_v4:{network4}"
    if not ip.is_global:
        return "non_global_v4"
    return None


def require_public(ip: IPAddress) -> None:
    reason = blocked_reason(ip)
    if reason is not None:
        raise EgressBlocked(reason)


# ----------------------------------------------------------------------------- hosts
def normalise_hostname(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    if not host:
        raise EgressBlocked("empty_host")
    try:
        ascii_host = idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise EgressBlocked("invalid_idna") from exc
    if len(ascii_host) > 253:
        raise EgressBlocked("host_too_long")
    labels = ascii_host.split(".")
    if not all(_LABEL.fullmatch(label) for label in labels):
        raise EgressBlocked("invalid_hostname")
    return ascii_host


def hostname_blocked_reason(host: str) -> str | None:
    if host in _BLOCKED_NAMES:
        return "internal_name"
    if "." not in host:
        return "single_label_name"
    if host.endswith(_BLOCKED_SUFFIXES):
        return "internal_suffix"
    last_label = host.rsplit(".", 1)[-1]
    if last_label.isdigit() or last_label.startswith("0x"):
        return "numeric_tld"  # looks like a malformed IP literal; never resolve it
    return None


# ------------------------------------------------------------------------------- URLs
def parse_url(raw: str, *, allowed_ports: tuple[int, ...] = (80, 443)) -> SafeURL:
    if not raw or len(raw) > MAX_URL_LENGTH:
        raise EgressBlocked("url_length")
    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in raw.strip()):
        raise EgressBlocked("url_control_characters")
    try:
        parts = urlsplit(raw.strip())
        port = parts.port
    except ValueError as exc:
        raise EgressBlocked("url_unparseable") from exc
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise EgressBlocked("scheme_not_allowed")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise EgressBlocked("credentials_in_url")
    hostname = parts.hostname
    if hostname is None:
        raise EgressBlocked("missing_host")
    if "%" in hostname:
        raise EgressBlocked("ipv6_zone_id")
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    if effective_port not in allowed_ports:
        raise EgressBlocked("port_not_allowed")

    ip_literal: IPAddress | None = None
    if parts.netloc.startswith("[") or ":" in hostname:
        try:
            ip_literal = IPv6Address(hostname)
        except ValueError as exc:
            raise EgressBlocked("invalid_ipv6") from exc
        host = str(ip_literal)
    else:
        ip_literal = parse_ipv4_literal(hostname)
        if ip_literal is not None:
            host = str(ip_literal)
        else:
            host = normalise_hostname(hostname)
            reason = hostname_blocked_reason(host)
            if reason is not None:
                raise EgressBlocked(reason)
    if ip_literal is not None:
        require_public(ip_literal)

    path = parts.path or "/"
    path_and_query = urlunsplit(("", "", path, parts.query, ""))
    return SafeURL(scheme, host, effective_port, path_and_query, ip_literal)


def is_ip_literal(host: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None
