"""Key material loaded once per process from settings.

Production and testing require every key (the configuration guards enforce it for production).
In **development only**, missing keys are generated in memory with a loud warning so that
``argus serve`` works out of the box - the cost is that sessions and encrypted values do not
survive a restart, which is exactly the right failure mode for a laptop.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from argus.core.config import ConfigurationError, Environment, Settings
from argus.core.crypto import Keyring, b64decode_secret
from argus.core.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class JWTKeys:
    active_kid: str
    private_keys: dict[str, Ed25519PrivateKey]

    @property
    def public_keys(self) -> dict[str, Ed25519PublicKey]:
        return {kid: key.public_key() for kid, key in self.private_keys.items()}

    @property
    def active_private_key(self) -> Ed25519PrivateKey:
        return self.private_keys[self.active_kid]


@dataclass(frozen=True)
class KeyMaterial:
    jwt: JWTKeys
    api_key_pepper: bytes
    audit_hmac_key: bytes
    signing_key: bytes
    encryption: Keyring
    ephemeral: bool = False


def _parse_jwt_keys(raw: str, active_kid: str) -> JWTKeys:
    try:
        mapping = json.loads(raw)
    except json.JSONDecodeError as exc:
        msg = "ARGUS_AUTH__JWT_SIGNING_KEYS must be a JSON object {kid: PEM}"
        raise ConfigurationError(msg) from exc
    if not isinstance(mapping, dict) or not mapping:
        msg = "ARGUS_AUTH__JWT_SIGNING_KEYS must be a non-empty JSON object"
        raise ConfigurationError(msg)
    keys: dict[str, Ed25519PrivateKey] = {}
    for kid, pem in mapping.items():
        try:
            key = serialization.load_pem_private_key(str(pem).encode(), password=None)
        except (ValueError, TypeError) as exc:
            msg = f"JWT signing key {kid!r} is not a valid PEM private key"
            raise ConfigurationError(msg) from exc
        if not isinstance(key, Ed25519PrivateKey):
            msg = f"JWT signing key {kid!r} must be an Ed25519 key (EdDSA)"
            raise ConfigurationError(msg)
        keys[str(kid)] = key
    if active_kid not in keys:
        msg = "ARGUS_AUTH__JWT_ACTIVE_KID does not name a configured key"
        raise ConfigurationError(msg)
    return JWTKeys(active_kid, keys)


def load_key_material(settings: Settings) -> KeyMaterial:
    auth, sec = settings.auth, settings.security
    complete = all(
        (
            auth.jwt_signing_keys,
            auth.jwt_active_kid,
            auth.api_key_pepper,
            sec.audit_hmac_key,
            sec.signing_key,
            sec.encryption_keys,
            sec.active_encryption_key,
        )
    )
    if not complete:
        if settings.environment is not Environment.DEVELOPMENT:
            msg = "key material is incomplete (run `argus keys generate`)"
            raise ConfigurationError(msg)
        log.warning(
            "keys.ephemeral",
            detail="development keys generated in memory; sessions will not survive a restart",
        )
        return KeyMaterial(
            jwt=JWTKeys("dev", {"dev": Ed25519PrivateKey.generate()}),
            api_key_pepper=os.urandom(32),
            audit_hmac_key=os.urandom(32),
            signing_key=os.urandom(32),
            encryption=Keyring.generate("dev"),
            ephemeral=True,
        )
    missing = [
        name
        for name, value in (
            ("ARGUS_AUTH__JWT_SIGNING_KEYS", auth.jwt_signing_keys),
            ("ARGUS_AUTH__JWT_ACTIVE_KID", auth.jwt_active_kid),
            ("ARGUS_AUTH__API_KEY_PEPPER", auth.api_key_pepper),
            ("ARGUS_SECURITY__AUDIT_HMAC_KEY", sec.audit_hmac_key),
            ("ARGUS_SECURITY__SIGNING_KEY", sec.signing_key),
            ("ARGUS_SECURITY__ENCRYPTION_KEYS", sec.encryption_keys),
            ("ARGUS_SECURITY__ACTIVE_ENCRYPTION_KEY", sec.active_encryption_key),
        )
        if not value
    ]
    if missing:  # settings validation rejects this first; never rely on `assert` for keys
        raise ConfigurationError(f"missing key material: {', '.join(missing)}")
    assert auth.jwt_signing_keys is not None  # nosec B101
    assert auth.jwt_active_kid is not None  # nosec B101
    assert auth.api_key_pepper is not None  # nosec B101
    assert sec.audit_hmac_key is not None  # nosec B101
    assert sec.signing_key is not None  # nosec B101
    assert sec.encryption_keys is not None  # nosec B101
    assert sec.active_encryption_key is not None  # nosec B101
    try:
        return KeyMaterial(
            jwt=_parse_jwt_keys(auth.jwt_signing_keys.get_secret_value(), auth.jwt_active_kid),
            api_key_pepper=b64decode_secret(
                auth.api_key_pepper.get_secret_value(), name="api key pepper"
            ),
            audit_hmac_key=b64decode_secret(
                sec.audit_hmac_key.get_secret_value(), name="audit HMAC key"
            ),
            signing_key=b64decode_secret(sec.signing_key.get_secret_value(), name="signing key"),
            encryption=Keyring.from_json(
                sec.encryption_keys.get_secret_value(), sec.active_encryption_key
            ),
        )
    except ValueError as exc:
        raise ConfigurationError(str(exc)) from exc
