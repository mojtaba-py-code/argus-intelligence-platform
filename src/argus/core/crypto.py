"""Cryptographic helpers built only from vetted primitives (``cryptography``, ``hmac``).

* :class:`Keyring` - AES-256-GCM with key ids. Ciphertexts carry the id of the key that produced
  them, so keys rotate without a big-bang re-encryption: new writes use the active key, old
  ciphertexts keep decrypting until a background job re-encrypts them.
  Associated data (AAD) binds a ciphertext to its context (e.g. the owning user id), so a
  ciphertext copied into another row fails to decrypt instead of silently working.
* :func:`hmac_sha256` - length-prefixed HMAC (no ambiguity between ``("ab", "c")`` and
  ``("a", "bc")``).
* :func:`sha256` / :func:`constant_time_equals`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_FORMAT_VERSION = b"\x01"
_NONCE_BYTES = 12
_KEY_BYTES = 32


class CryptoError(Exception):
    """Decryption failed (wrong key, wrong associated data, or tampered ciphertext)."""


def b64decode_secret(value: str, *, min_bytes: int = 32, name: str = "secret") -> bytes:
    try:
        raw = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        msg = f"{name} is not valid base64"
        raise ValueError(msg) from exc
    if len(raw) < min_bytes:
        msg = f"{name} must decode to at least {min_bytes} bytes"
        raise ValueError(msg)
    return raw


def generate_key_b64(nbytes: int = _KEY_BYTES) -> str:
    return base64.b64encode(secrets.token_bytes(nbytes)).decode("ascii")


def sha256(data: bytes | str) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes | str) -> str:
    return sha256(data).hex()


def hmac_sha256(key: bytes, *parts: bytes | str) -> bytes:
    mac = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        chunk = part.encode("utf-8") if isinstance(part, str) else part
        mac.update(len(chunk).to_bytes(8, "big"))
        mac.update(chunk)
    return mac.digest()


def constant_time_equals(a: bytes | str, b: bytes | str) -> bool:
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)


@dataclass(frozen=True, slots=True)
class _Key:
    key_id: str
    aead: AESGCM


class Keyring:
    """A set of AES-256-GCM keys addressed by id, one of which is active for encryption."""

    def __init__(self, keys: Mapping[str, bytes], active_key_id: str) -> None:
        if active_key_id not in keys:
            msg = "active key id is not in the keyring"
            raise ValueError(msg)
        parsed: dict[str, _Key] = {}
        for key_id, material in keys.items():
            if not key_id or len(key_id.encode()) > 32 or not key_id.isascii():
                msg = "key ids must be 1-32 ASCII characters"
                raise ValueError(msg)
            if len(material) != _KEY_BYTES:
                msg = f"encryption key {key_id!r} must be exactly 32 bytes"
                raise ValueError(msg)
            parsed[key_id] = _Key(key_id, AESGCM(material))
        self._keys = parsed
        self._active = parsed[active_key_id]

    @classmethod
    def from_json(cls, keys_json: str, active_key_id: str) -> Keyring:
        try:
            raw = json.loads(keys_json)
        except json.JSONDecodeError as exc:
            msg = "encryption keys must be a JSON object {key_id: base64}"
            raise ValueError(msg) from exc
        if not isinstance(raw, dict) or not raw:
            msg = "encryption keys must be a non-empty JSON object"
            raise ValueError(msg)
        keys = {
            str(key_id): b64decode_secret(str(value), min_bytes=_KEY_BYTES, name=f"key {key_id}")
            for key_id, value in raw.items()
        }
        return cls(keys, active_key_id)

    @classmethod
    def generate(cls, key_id: str = "dev") -> Keyring:
        return cls({key_id: os.urandom(_KEY_BYTES)}, key_id)

    @property
    def active_key_id(self) -> str:
        return self._active.key_id

    def key_ids(self) -> frozenset[str]:
        return frozenset(self._keys)

    def encrypt(self, plaintext: bytes, *, aad: bytes) -> bytes:
        nonce = os.urandom(_NONCE_BYTES)
        key_id = self._active.key_id.encode("ascii")
        header = _FORMAT_VERSION + len(key_id).to_bytes(1, "big") + key_id
        ciphertext = self._active.aead.encrypt(nonce, plaintext, header + aad)
        return header + nonce + ciphertext

    def decrypt(self, blob: bytes, *, aad: bytes) -> bytes:
        try:
            if blob[:1] != _FORMAT_VERSION:
                raise CryptoError("unknown ciphertext format")
            id_len = blob[1]
            key_id = blob[2 : 2 + id_len].decode("ascii")
            header = blob[: 2 + id_len]
            nonce = blob[2 + id_len : 2 + id_len + _NONCE_BYTES]
            ciphertext = blob[2 + id_len + _NONCE_BYTES :]
            key = self._keys.get(key_id)
            if key is None:
                raise CryptoError("ciphertext was produced by an unknown key")
            return key.aead.decrypt(nonce, ciphertext, header + aad)
        except (InvalidTag, IndexError, UnicodeDecodeError) as exc:
            raise CryptoError("decryption failed") from exc

    def needs_rotation(self, blob: bytes) -> bool:
        """True when ``blob`` was encrypted with a key other than the active one."""
        if len(blob) < 2:
            return True
        id_len = blob[1]
        return blob[2 : 2 + id_len] != self._active.key_id.encode("ascii")
