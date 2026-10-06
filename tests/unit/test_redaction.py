from __future__ import annotations

import pytest

from argus.core.redaction import REDACTED, contains_secret, is_sensitive_key, redact, redact_text

SECRETS = {
    "jwt": "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVlLWhlcmU",
    "argus_api_key": "argus_sk_ab12cd34ef56_Zx9YwVuTs8RqPo7NmLk6JiHg5FeDcBa4",
    "argus_refresh": "argus_rt_kq8HhRZf1fA7sN2wP0xGm3VbC9dE4yT6",
    "anthropic": "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "openai": "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123",
    "aws": "AKIAIOSFODNN7EXAMPLE",
    "github": "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "slack": "xoxb-1234567890-abcdefghij",
}


@pytest.mark.parametrize(("kind", "secret"), list(SECRETS.items()))
def test_credential_shapes_are_redacted_inside_free_text(kind: str, secret: str) -> None:
    text = f"request failed for {kind} with value {secret} at step 3"
    cleaned = redact_text(text)
    assert secret not in cleaned
    assert REDACTED in cleaned
    assert contains_secret(text)


def test_private_key_block_is_removed_entirely() -> None:
    pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEI\n-----END PRIVATE KEY-----"
    assert redact_text(f"key={pem}").count("MC4CAQ") == 0


def test_dsn_password_is_masked_but_host_kept_for_debugging() -> None:
    cleaned = redact_text("could not connect to postgresql://argus_app:hunter2@db:5432/argus")
    assert "hunter2" not in cleaned
    assert "argus_app:" in cleaned
    assert "@db:5432" in cleaned


@pytest.mark.parametrize(
    "text",
    [
        "password=hunter2",
        "PASSWORD: 'hunter2'",
        'api_key="hunter2"',
        "client_secret=hunter2&next=1",
        "Authorization: Bearer hunter2hunter2",
    ],
)
def test_assignments_and_auth_headers(text: str) -> None:
    assert "hunter2" not in redact_text(text)


def test_nested_structures_and_sensitive_keys() -> None:
    event = {
        "user": "alice",
        "password": "plain",
        "headers": {"Authorization": "Basic Zm9vOmJhcg==", "Accept": "json"},
        "items": [{"api_key": "k"}, "token argus_rt_kq8HhRZf1fA7sN2wP0xGm3VbC9dE4yT6"],
        "input_tokens": 1234,
        "session_id": "0192f4f6-0000-7000-8000-000000000000",
    }
    cleaned = redact(event)
    assert cleaned["password"] == REDACTED
    assert cleaned["headers"]["Authorization"] == REDACTED
    assert cleaned["headers"]["Accept"] == "json"
    assert cleaned["items"][0]["api_key"] == REDACTED
    assert "argus_rt_" not in cleaned["items"][1]
    assert cleaned["input_tokens"] == 1234  # counters are not secrets
    assert cleaned["session_id"] == event["session_id"]
    assert cleaned["user"] == "alice"


@pytest.mark.parametrize(
    ("key", "sensitive"),
    [
        ("password", True),
        ("new-password", True),
        ("refresh_token", True),
        ("X-Api-Key", True),
        ("cookie", True),
        ("mfa_code", True),
        ("input_tokens", False),
        ("token_type", False),
        ("password_changed_at", False),
        ("key_id", False),
        ("name", False),
    ],
)
def test_sensitive_key_classification(key: str, sensitive: bool) -> None:
    assert is_sensitive_key(key) is sensitive


def test_bytes_are_summarised_not_dumped() -> None:
    assert redact(b"\x00secret") == "[7 bytes]"


def test_deep_structures_are_truncated_not_recursed_forever() -> None:
    value: dict[str, object] = {}
    cursor = value
    for _ in range(50):
        child: dict[str, object] = {}
        cursor["child"] = child
        cursor = child
    assert "[TRUNCATED]" in str(redact(value))


def test_ordinary_text_is_untouched() -> None:
    text = "Research on PostgreSQL 16 tokenizer performance, 4,096 tokens per chunk."
    assert redact_text(text) == text
    assert not contains_secret(text)
