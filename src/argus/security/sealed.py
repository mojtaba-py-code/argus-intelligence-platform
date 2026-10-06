"""Envelope encryption for blobs at rest (ADR 0009).

Every object gets a fresh 256-bit data key (DEK). The payload is encrypted with the DEK
(AES-256-GCM) and the DEK is *wrapped* by the platform keyring - the key-encryption key (KEK),
which carries a key id, so KEKs rotate by re-wrapping a few dozen bytes per object instead of
re-encrypting gigabytes. Both encryptions bind the object's storage key as associated data: a
ciphertext copied to another key (another tenant's path, say) fails to decrypt instead of
silently serving the wrong document.

Object layout::

    b"ASB1" | u16 len(wrapped DEK) | wrapped DEK | 12-byte nonce | ciphertext + 16-byte tag

The storage backend (local disk or a bucket) therefore never holds plaintext, and a stolen bucket
is useless without the keyring.
"""

from __future__ import annotations

import os
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from argus.core.crypto import CryptoError, Keyring
from argus.infrastructure.storage import ObjectStore

_MAGIC: Final = b"ASB1"
_NONCE: Final = 12
_DEK: Final = 32


def _aad(kind: bytes, key: str) -> bytes:
    return kind + b"|" + key.encode("utf-8")


def seal(keyring: Keyring, key: str, plaintext: bytes) -> bytes:
    dek = AESGCM.generate_key(bit_length=_DEK * 8)
    wrapped = keyring.encrypt(dek, aad=_aad(b"dek", key))
    nonce = os.urandom(_NONCE)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, _aad(b"blob", key))
    return _MAGIC + len(wrapped).to_bytes(2, "big") + wrapped + nonce + ciphertext


def unseal(keyring: Keyring, key: str, blob: bytes) -> bytes:
    try:
        if blob[:4] != _MAGIC:
            raise CryptoError("not a sealed object")
        length = int.from_bytes(blob[4:6], "big")
        wrapped = blob[6 : 6 + length]
        nonce = blob[6 + length : 6 + length + _NONCE]
        ciphertext = blob[6 + length + _NONCE :]
        if len(wrapped) != length or len(nonce) != _NONCE:
            raise CryptoError("truncated sealed object")
        dek = keyring.decrypt(wrapped, aad=_aad(b"dek", key))
        return AESGCM(dek).decrypt(nonce, ciphertext, _aad(b"blob", key))
    except (InvalidTag, ValueError) as exc:
        raise CryptoError("sealed object failed authentication") from exc


def needs_rewrap(keyring: Keyring, blob: bytes) -> bool:
    """True when the DEK is wrapped by a KEK other than the active one (rotation job)."""
    length = int.from_bytes(blob[4:6], "big")
    return keyring.needs_rotation(blob[6 : 6 + length])


class SealedStore:
    """An :class:`ObjectStore` decorator that encrypts on write and authenticates on read."""

    def __init__(self, store: ObjectStore, keyring: Keyring) -> None:
        self.store = store
        self._keyring = keyring

    async def put(self, key: str, plaintext: bytes) -> int:
        blob = seal(self._keyring, key, plaintext)
        await self.store.put(key, blob)
        return len(blob)

    async def get(self, key: str) -> bytes:
        return unseal(self._keyring, key, await self.store.get(key))

    async def delete(self, key: str) -> None:
        await self.store.delete(key)

    async def exists(self, key: str) -> bool:
        return await self.store.exists(key)
