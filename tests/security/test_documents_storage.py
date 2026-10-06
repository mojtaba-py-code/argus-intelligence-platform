"""Phase 7: storage, encryption at rest, signed links, malware scanning and upload validation."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import boto3
import pytest
from moto import mock_aws

from argus.core.crypto import CryptoError, Keyring
from argus.infrastructure.malware import ClamAVScanner, ScannerUnavailable, SignatureScanner
from argus.infrastructure.storage import LocalObjectStore, ObjectNotFound, validate_key
from argus.infrastructure.storage.s3 import S3ObjectStore
from argus.modules.documents.validation import (
    UnsupportedDocument,
    clean_filename,
    content_disposition,
    decide_kind,
)
from argus.security.links import InvalidLink, issue_link_token, verify_link_token
from argus.security.sealed import SealedStore, needs_rewrap, seal, unseal
from tests.document_fixtures import FakeClamd, eicar, make_docx, make_pdf, make_zip

pytestmark = pytest.mark.security
KEY = f"org/{uuid4()}/project/{uuid4()}/documents/{uuid4()}"


# ------------------------------------------------------------------------------- storage
@pytest.mark.parametrize(
    "key",
    [
        "../etc/passwd",
        "/abs/key",
        "a//b",
        "Upper/Case",
        "a\\b",
        "",
        "a/../b",
        "a/./b",
        "x" * 200,
        "a/b/",
    ],
)
def test_object_keys_are_validated(key: str) -> None:
    with pytest.raises(ValueError, match="invalid object key"):
        validate_key(key)


async def test_local_store_round_trip_is_atomic_and_contained(tmp_path: Path) -> None:
    store = LocalObjectStore(tmp_path)
    await store.put(KEY, b"payload")
    assert await store.get(KEY) == b"payload"
    assert await store.exists(KEY)
    assert not any(tmp_path.rglob(".upload-*"))  # no temp files left behind
    await store.delete(KEY)
    await store.delete(KEY)  # idempotent
    assert not await store.exists(KEY)
    with pytest.raises(ObjectNotFound):
        await store.get(KEY)
    with pytest.raises(ValueError, match="invalid object key"):
        await store.put("../escape", b"x")


async def test_s3_store_against_a_mocked_bucket() -> None:
    with mock_aws():
        client = boto3.client(
            "s3",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
        )
        client.create_bucket(Bucket="argus-test")
        store = S3ObjectStore(client, "argus-test", server_side_encryption="AES256")
        await store.put(KEY, b"payload")
        assert await store.get(KEY) == b"payload"
        assert client.head_object(Bucket="argus-test", Key=KEY)["ServerSideEncryption"] == "AES256"
        assert await store.exists(KEY)
        await store.delete(KEY)
        assert not await store.exists(KEY)
        with pytest.raises(ObjectNotFound):
            await store.get(KEY)
        await store.aclose()


# ----------------------------------------------------------------------- encryption at rest
def keyring(key_id: str = "k1") -> Keyring:
    return Keyring({key_id: os.urandom(32)}, key_id)


async def test_sealed_objects_hold_no_plaintext_and_round_trip(tmp_path: Path) -> None:
    ring = keyring()
    sealed = SealedStore(LocalObjectStore(tmp_path), ring)
    secret = b"CONFIDENTIAL quarterly numbers " * 10
    await sealed.put(KEY, secret)
    raw = (tmp_path / KEY).read_bytes()
    assert raw.startswith(b"ASB1")
    assert b"CONFIDENTIAL" not in raw
    assert await sealed.get(KEY) == secret


def test_ciphertext_is_bound_to_its_storage_key() -> None:
    ring = keyring()
    blob = seal(ring, KEY, b"tenant A data")
    other_tenant_key = f"org/{uuid4()}/project/{uuid4()}/documents/{uuid4()}"
    with pytest.raises(CryptoError):
        unseal(ring, other_tenant_key, blob)  # copied to another path: refused


@pytest.mark.parametrize("position", [0, 5, 40, -1])
def test_tampering_is_detected(position: int) -> None:
    ring = keyring()
    blob = bytearray(seal(ring, KEY, b"payload"))
    blob[position] ^= 0x01
    with pytest.raises(CryptoError):
        unseal(ring, KEY, bytes(blob))


def test_wrong_keyring_and_kek_rotation() -> None:
    old_material = os.urandom(32)
    blob = seal(Keyring({"old": old_material}, "old"), KEY, b"payload")
    with pytest.raises(CryptoError):
        unseal(keyring("old"), KEY, blob)  # same key id, different key material
    rotated = Keyring({"old": old_material, "new": os.urandom(32)}, "new")
    assert unseal(rotated, KEY, blob) == b"payload"  # objects under the old KEK keep opening
    assert needs_rewrap(rotated, blob)
    assert not needs_rewrap(rotated, seal(rotated, KEY, b"payload"))
    with pytest.raises(CryptoError):
        unseal(rotated, KEY, b"not sealed")


# --------------------------------------------------------------------------- signed links
NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
SIGNING_KEY = b"k" * 32


def test_links_round_trip_and_expire() -> None:
    token, expires = issue_link_token(
        {"d": "doc"}, key=SIGNING_KEY, purpose="download", now=NOW, ttl_s=300
    )
    assert expires == NOW + timedelta(seconds=300)
    assert verify_link_token(token, key=SIGNING_KEY, purpose="download", now=NOW)["d"] == "doc"
    with pytest.raises(InvalidLink):
        verify_link_token(
            token, key=SIGNING_KEY, purpose="download", now=NOW + timedelta(seconds=300)
        )


def test_links_resist_forgery() -> None:
    token, _ = issue_link_token(
        {"d": "doc"}, key=SIGNING_KEY, purpose="download", now=NOW, ttl_s=300
    )
    payload, mac = token.split(".")
    forged_payload = payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB")
    for candidate in (
        f"{forged_payload}.{mac}",
        f"{payload}.{mac[:-1]}x",
        token + "x",
        "x" * 2000,
        "no-dot",
        "a.b.c",
    ):
        with pytest.raises(InvalidLink):
            verify_link_token(candidate, key=SIGNING_KEY, purpose="download", now=NOW)
    with pytest.raises(InvalidLink):
        verify_link_token(token, key=b"z" * 32, purpose="download", now=NOW)
    with pytest.raises(InvalidLink):
        verify_link_token(token, key=SIGNING_KEY, purpose="other-purpose", now=NOW)


# -------------------------------------------------------------------------------- scanning
async def test_signature_scanner_knows_only_the_test_file() -> None:
    scanner = SignatureScanner()
    assert not (await scanner.scan(eicar())).clean
    assert not (await scanner.scan(eicar() + b"\r\n  ")).clean
    assert (await scanner.scan(b"ordinary text")).clean
    assert (await scanner.scan(eicar() + b"x" * 100)).clean  # not the test-file form


async def test_clamav_adapter_speaks_instream() -> None:
    async with FakeClamd().running() as clamd:
        scanner = ClamAVScanner("127.0.0.1", clamd.port, timeout_s=5, chunk_bytes=7)
        clean = await scanner.scan(b"a perfectly normal document")
        infected = await scanner.scan(b"prefix MALWARE-MARKER suffix")
        assert clean.clean
        assert (infected.clean, infected.signature, infected.engine) == (
            False,
            "Test.Malware",
            "clamav",
        )
        assert clamd.received[0] == b"a perfectly normal document"  # chunking reassembles
        assert await scanner.ping()


async def test_clamav_errors_are_never_treated_as_clean() -> None:
    async with FakeClamd(
        reply_override=b"INSTREAM size limit exceeded. ERROR\x00"
    ).running() as clamd:
        with pytest.raises(ScannerUnavailable):
            await ClamAVScanner("127.0.0.1", clamd.port, timeout_s=5).scan(b"data")
    unreachable = ClamAVScanner("127.0.0.1", 9, timeout_s=1)
    with pytest.raises(ScannerUnavailable):
        await unreachable.scan(b"data")
    assert not await unreachable.ping()


# ---------------------------------------------------------------------- upload validation
@pytest.mark.parametrize(
    ("filename", "declared", "data", "kind"),
    [
        ("report.pdf", "application/pdf", make_pdf(), "pdf"),
        ("memo.docx", "application/octet-stream", make_docx(), "docx"),
        ("notes.md", "text/markdown", b"# Notes", "markdown"),
        ("notes.txt", None, b"plain text", "text"),
        ("data.csv", "text/csv", b"a,b\n1,2\n", "csv"),
        ("data.json", "application/json", b'{"a": 1}', "json"),
        ("page.HTML", "text/html; charset=utf-8", b"<html><body>x</body></html>", "html"),
    ],
)
def test_accepted_documents(filename: str, declared: str | None, data: bytes, kind: str) -> None:
    assert decide_kind(filename, declared, data)[0] == kind


@pytest.mark.parametrize(
    ("filename", "declared", "data", "reason"),
    [
        ("invoice.pdf", None, b"MZ\x90\x00 windows executable", "dangerous_content"),
        ("script.txt", None, b"#!/bin/sh\nrm -rf /", "dangerous_content"),
        ("report.pdf", None, b"<html>not a pdf</html>", "content_mismatch"),
        ("memo.docx", None, make_zip({"readme.txt": b"x"}), "content_mismatch"),
        ("memo.docx", None, make_pdf(), "content_mismatch"),
        ("data.json", None, b"{not json", "content_mismatch"),
        ("notes.txt", "application/pdf", b"plain", "mime_mismatch"),
        ("program.exe", None, b"MZ", "extension"),
        ("archive.zip", None, make_zip({"a": b"b"}), "extension"),
        ("noextension", None, b"text", "extension"),
        ("empty.txt", None, b"", "empty"),
    ],
)
def test_rejected_documents(filename: str, declared: str | None, data: bytes, reason: str) -> None:
    with pytest.raises(UnsupportedDocument) as caught:
        decide_kind(filename, declared, data)
    assert caught.value.reason == reason
    assert caught.value.status == 415


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("../../etc/passwd", "passwd"),
        ("C:\\Users\\me\\report.pdf", "report.pdf"),
        ("invoice\u202efdp.exe", "invoicefdp.exe"),  # right-to-left override removed
        ("bad\x00name\x07.txt", "badname.txt"),
        ('quo"te<>|?*.md', "quote.md"),
        ("   ...   ", "document"),
        (None, "document"),
        ("گزارش مالی.pdf", "گزارش مالی.pdf"),
    ],
)
def test_filenames_are_display_safe(raw: str | None, clean: str) -> None:
    assert clean_filename(raw) == clean


def test_long_filenames_keep_their_extension() -> None:
    name = clean_filename("a" * 500 + ".pdf")
    assert len(name) <= 200
    assert name.endswith(".pdf")


def test_content_disposition_is_safe_for_any_name() -> None:
    header = content_disposition('گزارش "Q3".pdf')
    assert header.startswith('attachment; filename="')
    assert "filename*=UTF-8''%DA%AF" in header
    assert '"Q3"' not in header  # quotes cannot break out of the parameter
