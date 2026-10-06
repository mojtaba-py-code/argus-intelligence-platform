"""SSRF guard: URL, host and IP validation, including encodings that bypass naive filters."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.security.ssrf import (
    EgressBlocked,
    blocked_reason,
    parse_ipv4_literal,
    parse_url,
)

pytestmark = pytest.mark.security

BLOCKED_URLS = [
    "http://localhost/",
    "http://LOCALHOST./admin",
    "http://sub.localhost/",
    "http://127.0.0.1/",
    "http://127.1/",
    "http://127.0.1/",
    "http://2130706433/",
    "http://0x7f000001/",
    "http://0x7f.1/",
    "http://0177.0.0.1/",
    "http://0177.1/",
    "http://017700000001/",
    "http://[::1]/",
    "http://[0:0:0:0:0:0:0:1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7f00:1]/",
    "http://[::127.0.0.1]/",
    "http://169.254.169.254/latest/meta-data/",
    "http://0xa9fea9fe/",
    "http://[fd00:ec2::254]/latest/",
    "http://100.100.100.200/",
    "http://10.0.0.1/",
    "http://10.1/",
    "http://172.16.0.1/",
    "http://172.31.255.255/",
    "http://192.168.1.1/",
    "http://0.0.0.0/",
    "http://0/",
    "http://255.255.255.255/",
    "http://224.0.0.1/",
    "http://198.18.0.1/",
    "http://[64:ff9b::7f00:1]/",
    "http://[64:ff9b::a00:1]/",
    "http://[2002:7f00:1::]/",
    "http://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/",
    "http://[fc00::1]/",
    "http://[fe80::1]/",
    "http://[ff02::1]/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata/",
    "http://intranet/",
    "http://printer.local/",
    "http://db.internal/",
    "http://router.lan/",
    "http://foo.home.arpa/",
    "http://1.0.0.127.in-addr.arpa/",
    "http://example.test/",
    "http://999.1.1.1/",
    "http://1.2.3.4.5/",
    "file:///etc/passwd",
    "gopher://example.com/_GET",
    "ftp://example.com/",
    "javascript:alert(1)",
    "data:text/html,<script>",
    "http://user:pass@example.com/",
    "http://user@example.com/",
    "http://example.com:22/",
    "http://example.com:6379/",
    "http://example.com:8080/",
    "http://[fe80::1%25eth0]/",
    "http:///path-only",
    "http://exa mple.com/",
    "http://example.com/\x00",
    "",
    "https://" + "a" * 2100 + ".com/",
]
ALLOWED_URLS = [
    ("https://example.com/path?q=1", "example.com"),
    ("https://EXAMPLE.com./docs", "example.com"),
    ("http://93.184.216.34/", "93.184.216.34"),
    ("https://[2606:4700:4700::1111]/", "2606:4700:4700::1111"),
    ("https://bücher.de/katalog", "xn--bcher-kva.de"),
    ("https://[64:ff9b::808:808]/", "64:ff9b::808:808"),  # NAT64 of a public address
    ("https://example.com:443/", "example.com"),
]


@pytest.mark.parametrize("url", BLOCKED_URLS)
def test_dangerous_urls_are_blocked(url: str) -> None:
    with pytest.raises(EgressBlocked):
        parse_url(url)


@pytest.mark.parametrize(("url", "host"), ALLOWED_URLS)
def test_public_urls_are_normalised(url: str, host: str) -> None:
    parsed = parse_url(url)
    assert parsed.host == host
    assert parsed.scheme in {"http", "https"}


def test_url_keeps_path_and_query_but_drops_fragment() -> None:
    parsed = parse_url("https://example.com/a/b?x=1#frag")
    assert str(parsed) == "https://example.com/a/b?x=1"


@pytest.mark.parametrize(
    ("literal", "expected"),
    [
        ("127.0.0.1", "127.0.0.1"),
        ("2130706433", "127.0.0.1"),
        ("0x7f000001", "127.0.0.1"),
        ("0177.0.0.01", "127.0.0.1"),
        ("127.1", "127.0.0.1"),
        ("10.1.257", "10.1.1.1"),
        ("0xc0.0xa8.0x1.0x1", "192.168.1.1"),
        ("1.2.3.4.", "1.2.3.4"),
    ],
)
def test_inet_aton_forms(literal: str, expected: str) -> None:
    assert parse_ipv4_literal(literal) == IPv4Address(expected)


@pytest.mark.parametrize(
    "literal", ["256.1.1.1", "1.2.3.4.5", "08.1.1.1", "example", "1..2", "0x1g"]
)
def test_invalid_ipv4_literals(literal: str) -> None:
    assert parse_ipv4_literal(literal) is None


_PRIVATE_V4 = st.one_of(
    st.integers(0x0A000000, 0x0AFFFFFF),  # 10/8
    st.integers(0x7F000000, 0x7FFFFFFF),  # 127/8
    st.integers(0xAC100000, 0xAC1FFFFF),  # 172.16/12
    st.integers(0xC0A80000, 0xC0A8FFFF),  # 192.168/16
    st.integers(0xA9FE0000, 0xA9FEFFFF),  # 169.254/16
    st.integers(0x64400000, 0x647FFFFF),  # 100.64/10
)


@given(_PRIVATE_V4)
def test_every_encoding_of_a_private_address_is_blocked(value: int) -> None:
    dotted = str(IPv4Address(value))
    octal = ".".join(f"0{int(part):o}" for part in dotted.split("."))
    for host in (dotted, str(value), hex(value), octal, f"[::ffff:{dotted}]"):
        with pytest.raises(EgressBlocked):
            parse_url(f"http://{host}/")


@given(st.integers(0, 2**32 - 1))
def test_parser_agrees_with_ipaddress_for_dotted_quads(value: int) -> None:
    dotted = str(IPv4Address(value))
    assert parse_ipv4_literal(dotted) == IPv4Address(value)
    assert parse_ipv4_literal(str(value)) == IPv4Address(value)


@given(st.integers(0, 2**32 - 1))
def test_blocked_reason_is_consistent_with_is_global(value: int) -> None:
    address = IPv4Address(value)
    if blocked_reason(address) is None:
        assert address.is_global


@pytest.mark.parametrize(
    "address",
    ["::ffff:8.8.8.8", "2002:808:808::1", "2001:0:4136:e378::1", "64:ff9b:1::1", "::"],
)
def test_ipv6_transition_forms_are_never_trusted(address: str) -> None:
    parsed = ip_address(address)
    assert isinstance(parsed, IPv6Address)
    assert blocked_reason(parsed) is not None
