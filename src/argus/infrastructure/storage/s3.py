"""S3 and S3-compatible (MinIO, Ceph, R2) backend.

boto3 is synchronous; calls run in worker threads (boto3 *clients* are thread-safe). The bucket
should be private with "block public access" on; objects are already encrypted by the
application, and server-side encryption can be layered on top (``s3_server_side_encryption``).
Pre-signed bucket URLs are deliberately not used: downloads go through the API, which decrypts,
re-checks authorisation and writes the audit record (ADR 0009).
"""

from __future__ import annotations

import asyncio
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from argus.core.config import StorageSettings
from argus.infrastructure.storage.store import ObjectNotFound, StorageError, validate_key

_MISSING = frozenset({"NoSuchKey", "404", "NotFound"})


class S3ObjectStore:
    name = "s3"

    def __init__(
        self, client: Any, bucket: str, *, server_side_encryption: str | None = None
    ) -> None:
        self._client = client
        self._bucket = bucket
        self._sse = server_side_encryption

    @classmethod
    def from_settings(cls, settings: StorageSettings) -> S3ObjectStore:
        if settings.s3_bucket is None:  # settings validation rejects this first
            msg = "ARGUS_STORAGE__S3_BUCKET is required for the s3 backend"
            raise ValueError(msg)
        client = boto3.session.Session().client(
            "s3",
            endpoint_url=str(settings.s3_endpoint_url) if settings.s3_endpoint_url else None,
            region_name=settings.s3_region,
            aws_access_key_id=(
                settings.s3_access_key_id.get_secret_value() if settings.s3_access_key_id else None
            ),
            aws_secret_access_key=(
                settings.s3_secret_access_key.get_secret_value()
                if settings.s3_secret_access_key
                else None
            ),
            config=Config(
                signature_version="s3v4",
                retries={"max_attempts": 3, "mode": "standard"},
                connect_timeout=5,
                read_timeout=30,
            ),
        )
        return cls(
            client, settings.s3_bucket, server_side_encryption=settings.s3_server_side_encryption
        )

    async def _call(self, method: str, **kwargs: Any) -> Any:
        try:
            return await asyncio.to_thread(
                getattr(self._client, method), Bucket=self._bucket, **kwargs
            )
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code in _MISSING:
                raise ObjectNotFound(kwargs.get("Key", "")) from None
            raise StorageError(f"s3 {method} failed: {code or 'error'}") from exc
        except BotoCoreError as exc:
            raise StorageError(f"s3 {method} failed: {type(exc).__name__}") from exc

    async def put(self, key: str, data: bytes) -> None:
        extra: dict[str, Any] = {"ServerSideEncryption": self._sse} if self._sse else {}
        await self._call(
            "put_object",
            Key=validate_key(key),
            Body=data,
            ContentType="application/octet-stream",
            **extra,
        )

    async def get(self, key: str) -> bytes:
        response = await self._call("get_object", Key=validate_key(key))
        try:
            data: bytes = await asyncio.to_thread(response["Body"].read)
        except (BotoCoreError, OSError) as exc:
            raise StorageError(f"s3 read failed: {type(exc).__name__}") from exc
        return data

    async def delete(self, key: str) -> None:
        await self._call("delete_object", Key=validate_key(key))  # S3 deletes are idempotent

    async def exists(self, key: str) -> bool:
        try:
            await self._call("head_object", Key=validate_key(key))
        except ObjectNotFound:
            return False
        return True

    async def aclose(self) -> None:
        await asyncio.to_thread(self._client.close)
