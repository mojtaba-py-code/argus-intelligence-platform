"""Blob storage adapters. They move opaque bytes: encryption happens above this layer
(:mod:`argus.security.sealed`), so neither backend ever holds plaintext."""

from argus.infrastructure.storage.store import (
    LocalObjectStore,
    ObjectNotFound,
    ObjectStore,
    StorageError,
    create_object_store,
    validate_key,
)

__all__ = [
    "LocalObjectStore",
    "ObjectNotFound",
    "ObjectStore",
    "StorageError",
    "create_object_store",
    "validate_key",
]
