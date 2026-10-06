"""Signed, expiring capability links (document downloads).

A link is ``<payload>.<mac>``: base64url JSON claims plus an HMAC-SHA256 over a purpose label and
the payload, keyed by ``security.signing_key``. Links are short-lived (``storage.signed_url_ttl_s``)
and carry *who* created them; the download endpoint re-checks that person's session and
permissions at click time, so a link stops working when its creator logs out, is removed from the
organisation or loses access to the document - not only when it expires.

Links are bearer capabilities within their lifetime (browsers re-request downloads, so they are
not single-use); keep the TTL short and never log full link URLs (the access log redacts them).
"""

from __future__ import annotations

import base64
import binascii
import json
import secrets
from datetime import datetime
from typing import Any, Final

from argus.core.crypto import constant_time_equals, hmac_sha256

_VERSION: Final = 1
MAX_LINK_CHARS: Final = 1024


class InvalidLink(Exception):
    """Malformed, forged, expired or for another purpose - deliberately not distinguished."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _mac(key: bytes, purpose: str, payload: str) -> str:
    return _b64(hmac_sha256(key, b"argus-link", purpose, payload))


def issue_link_token(
    claims: dict[str, Any], *, key: bytes, purpose: str, now: datetime, ttl_s: int
) -> tuple[str, datetime]:
    expires = int(now.timestamp()) + ttl_s
    body = {**claims, "v": _VERSION, "pur": purpose, "exp": expires, "jti": secrets.token_hex(8)}
    payload = _b64(json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    token = f"{payload}.{_mac(key, purpose, payload)}"
    if len(token) > MAX_LINK_CHARS:
        msg = "link claims are too large"
        raise ValueError(msg)
    return token, datetime.fromtimestamp(expires, tz=now.tzinfo)


def verify_link_token(token: str, *, key: bytes, purpose: str, now: datetime) -> dict[str, Any]:
    if len(token) > MAX_LINK_CHARS or token.count(".") != 1:
        raise InvalidLink
    payload, mac = token.split(".")
    if not constant_time_equals(mac, _mac(key, purpose, payload)):
        raise InvalidLink
    try:
        claims = json.loads(_unb64(payload))
    except (binascii.Error, ValueError):
        raise InvalidLink from None
    if (
        not isinstance(claims, dict)
        or claims.get("v") != _VERSION
        or claims.get("pur") != purpose
        or not isinstance(claims.get("exp"), int)
        or claims["exp"] <= int(now.timestamp())
    ):
        raise InvalidLink
    return claims
