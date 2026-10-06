"""Access tokens: short-lived JWTs signed with Ed25519 (EdDSA). See ADR 0005.

Verification is deliberately strict:
* the algorithm is pinned (``EdDSA`` only - no ``none``, no HS/RS confusion);
* the key is chosen by ``kid`` from a fixed keyring (never from a URL in the token header);
* ``typ`` must be ``at+jwt`` (RFC 9068), so a different kind of token cannot be replayed as an
  access token;
* ``iss``, ``aud``, ``exp``, ``nbf``, ``iat``, ``sub``, ``sid`` and ``jti`` are all required.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import jwt
from cryptography.hazmat.primitives import serialization

from argus.core.clock import Clock, SystemClock
from argus.core.errors import InvalidCredentials
from argus.core.ids import uuid7
from argus.security.keys import JWTKeys

ACCESS_TOKEN_TYPE = "at+jwt"  # noqa: S105  # nosec B105
_LEEWAY_S = 5
_REQUIRED = ["exp", "iat", "nbf", "iss", "aud", "sub", "sid", "jti"]


@dataclass(frozen=True, slots=True)
class AccessClaims:
    user_id: UUID
    session_id: UUID
    token_id: str
    issued_at: datetime
    expires_at: datetime
    amr: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IssuedToken:
    token: str
    expires_at: datetime


class TokenService:
    def __init__(
        self,
        keys: JWTKeys,
        *,
        issuer: str,
        audience: str,
        ttl_s: int,
        clock: Clock | None = None,
    ) -> None:
        self._keys = keys
        self._public = keys.public_keys
        self._issuer = issuer
        self._audience = audience
        self._ttl = timedelta(seconds=ttl_s)
        self._clock = clock or SystemClock()

    def issue_access_token(
        self, *, user_id: UUID, session_id: UUID, amr: tuple[str, ...], now: datetime
    ) -> IssuedToken:
        expires_at = now + self._ttl
        payload: dict[str, Any] = {
            "iss": self._issuer,
            "aud": self._audience,
            "sub": str(user_id),
            "sid": str(session_id),
            "jti": uuid7().hex,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "amr": list(amr),
        }
        token = jwt.encode(
            payload,
            self._keys.active_private_key,
            algorithm="EdDSA",
            headers={"kid": self._keys.active_kid, "typ": ACCESS_TOKEN_TYPE},
        )
        return IssuedToken(token, expires_at)

    def verify_access_token(self, token: str) -> AccessClaims:
        invalid = InvalidCredentials("The access token is invalid or expired.")
        if len(token) > 4096:
            raise invalid
        try:
            header = jwt.get_unverified_header(token)
            key = self._public.get(str(header.get("kid", "")))
            if (
                key is None
                or header.get("typ") != ACCESS_TOKEN_TYPE
                or header.get("alg") != "EdDSA"
            ):
                raise invalid
            # Signature, issuer, audience and claim presence by PyJWT; the time claims against our
            # own clock (the same clock that issued them - consistent in tests and across hosts).
            claims = jwt.decode(
                token,
                key,
                algorithms=["EdDSA"],
                audience=self._audience,
                issuer=self._issuer,
                options={
                    "require": _REQUIRED,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )
            now = self._clock.now().timestamp()
            expires, not_before, issued = int(claims["exp"]), int(claims["nbf"]), int(claims["iat"])
            if (
                expires < now - _LEEWAY_S
                or not_before > now + _LEEWAY_S
                or issued > now + _LEEWAY_S
            ):
                raise invalid
            amr = claims.get("amr", [])
            return AccessClaims(
                user_id=UUID(claims["sub"]),
                session_id=UUID(claims["sid"]),
                token_id=str(claims["jti"]),
                issued_at=datetime.fromtimestamp(issued, UTC),
                expires_at=datetime.fromtimestamp(expires, UTC),
                amr=tuple(str(item) for item in amr) if isinstance(amr, list) else (),
            )
        except (jwt.PyJWTError, ValueError, KeyError, TypeError, OverflowError) as exc:
            raise invalid from exc

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        """Public verification keys as a JWKS document (RFC 7517, OKP/Ed25519)."""
        keys: list[dict[str, str]] = []
        for kid, public in sorted(self._public.items()):
            raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            keys.append(
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": kid,
                    "use": "sig",
                    "alg": "EdDSA",
                    "x": base64.urlsafe_b64encode(raw).decode().rstrip("="),
                }
            )
        return {"keys": keys}
