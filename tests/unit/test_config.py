from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from argus.core.config import (
    ConfigurationError,
    Environment,
    Settings,
    build_settings,
    check_unknown_variables,
    load_settings,
)
from tests.support import TEST_B64_32, TEST_ENC_KEYS, TEST_JWT_KID, TEST_JWT_PEM, make_settings

DB_PASSWORD = "s3cret-db-password"


def _production(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "_env_file": None,
        "environment": "production",
        "database": {
            "url": f"postgresql+asyncpg://argus_app:{DB_PASSWORD}@db.internal:5432/argus",
            "migration_url": "postgresql+asyncpg://argus_owner:other@db.internal:5432/argus",
            "tls_mode": "verify-full",
        },
        "redis": {"url": "rediss://:pw@redis.internal:6380/0"},
        "http": {
            "public_base_url": "https://api.example.com",
            "allowed_hosts": ["api.example.com"],
            "expose_docs": False,
        },
        "auth": {
            "jwt_signing_keys": json.dumps({TEST_JWT_KID: TEST_JWT_PEM}),
            "jwt_active_kid": TEST_JWT_KID,
            "api_key_pepper": TEST_B64_32,
        },
        "security": {
            "encryption_keys": TEST_ENC_KEYS,
            "active_encryption_key": "t1",
            "audit_hmac_key": TEST_B64_32,
            "signing_key": TEST_B64_32,
        },
        "email": {"backend": "smtp", "smtp_host": "smtp.example.com"},
        "documents": {"scanner": "clamav", "clamav_host": "clamav.internal"},
        "observability": {"metrics_token": "scrape-token-value"},
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(values.get(key), dict):
            values[key] = {**values[key], **value}
        else:
            values[key] = value
    return values


def test_development_defaults_are_valid() -> None:
    settings = build_settings(_env_file=None)
    assert settings.environment is Environment.DEVELOPMENT
    assert not settings.environment.is_production_like


def test_production_with_complete_configuration_starts() -> None:
    assert build_settings(**_production()).environment is Environment.PRODUCTION


@pytest.mark.parametrize("environment", ["production", "staging"])
def test_production_like_rejects_defaults_and_lists_every_problem(environment: str) -> None:
    with pytest.raises(ConfigurationError) as caught:
        build_settings(_env_file=None, environment=environment)
    message = str(caught.value)
    for variable in (
        "ARGUS_HTTP__EXPOSE_DOCS",
        "ARGUS_DATABASE__URL",
        "ARGUS_REDIS__URL",
        "ARGUS_AUTH__JWT_SIGNING_KEYS",
        "ARGUS_AUTH__API_KEY_PEPPER",
        "ARGUS_SECURITY__ENCRYPTION_KEYS",
        "ARGUS_HTTP__PUBLIC_BASE_URL",
        "ARGUS_DOCUMENTS__SCANNER",
    ):
        assert variable in message


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"debug": True}, "ARGUS_DEBUG"),
        ({"http": {"allowed_hosts": ["*"]}}, "ALLOWED_HOSTS"),
        ({"http": {"cors_origins": ["*"]}}, "CORS_ORIGINS"),
        ({"http": {"expose_docs": True}}, "EXPOSE_DOCS"),
        ({"documents": {"scanner": "signature"}}, "ARGUS_DOCUMENTS__SCANNER"),
        ({"redis": {"url": "redis://redis.internal:6379/0"}}, "rediss://"),
        ({"database": {"tls_mode": "prefer"}}, "TLS_MODE"),
        ({"observability": {"metrics_token": None}}, "METRICS_TOKEN"),
        ({"observability": {"log_level": "DEBUG"}}, "LOG_LEVEL"),
        ({"email": {"backend": "memory"}}, "ARGUS_EMAIL__BACKEND"),
        ({"database": {"echo": True}}, "ECHO"),
        ({"auth": {"api_key_pepper": "c2hvcnQ="}}, "API_KEY_PEPPER"),
        ({"observability": {"otel_enabled": True}}, "OTEL_ENDPOINT is required"),
        (
            {"observability": {"otel_endpoint": "http://collector.internal:4318"}},
            "OTEL_ENDPOINT must use https",
        ),
    ],
)
def test_each_production_rule(override: dict[str, Any], expected: str) -> None:
    with pytest.raises(ConfigurationError, match=expected):
        build_settings(**_production(**override))


def test_runtime_processes_need_no_owner_credentials() -> None:
    """Least privilege: the API, workers and scheduler run without the schema owner's DSN."""
    settings = build_settings(**_production(database={"migration_url": None}))
    assert settings.database.migration_url is None


def test_the_owner_dsn_must_differ_from_the_runtime_dsn() -> None:
    runtime = f"postgresql+asyncpg://argus_app:{DB_PASSWORD}@db.internal:5432/argus"
    with pytest.raises(ConfigurationError, match="MIGRATION_URL must differ"):
        build_settings(**_production(database={"migration_url": runtime}))


def test_production_accepts_tracing_over_tls() -> None:
    settings = build_settings(
        **_production(
            observability={"otel_enabled": True, "otel_endpoint": "https://collector.internal:4318"}
        )
    )
    assert settings.observability.otel_enabled


def test_configuration_errors_never_echo_secret_values() -> None:
    with pytest.raises(ConfigurationError) as caught:
        build_settings(**_production(debug=True))
    message = str(caught.value)
    assert DB_PASSWORD not in message
    assert TEST_B64_32 not in message
    assert "BEGIN PRIVATE KEY" not in message


def test_plaintext_internal_traffic_requires_explicit_acceptance() -> None:
    settings = build_settings(
        **_production(
            redis={"url": "redis://redis.internal:6379/0"},
            database={"tls_mode": "disable"},
            security={"allow_plaintext_internal_traffic": True},
        )
    )
    assert settings.security.allow_plaintext_internal_traffic


def test_unknown_variable_is_rejected_with_a_suggestion() -> None:
    with pytest.raises(
        ConfigurationError, match=r"ARGUS_DATABSE__URL.*did you mean ARGUS_DATABASE__URL"
    ):
        check_unknown_variables({"ARGUS_DATABSE__URL": "x"})


def test_known_and_test_variables_are_accepted() -> None:
    check_unknown_variables(
        {
            "ARGUS_DATABASE__URL": "x",
            "ARGUS_AUTH__API_KEY_PEPPER_FILE": "/run/secrets/pepper",
            "ARGUS_TEST_DATABASE_URL": "x",
            "PATH": "/usr/bin",
        }
    )


def test_secret_file_variables_are_loaded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = tmp_path / "pepper"
    secret.write_text(TEST_B64_32 + "\n", encoding="utf-8")
    monkeypatch.setenv("ARGUS_AUTH__API_KEY_PEPPER_FILE", str(secret))
    settings = load_settings(_env_file=None)
    assert settings.auth.api_key_pepper is not None
    assert settings.auth.api_key_pepper.get_secret_value() == TEST_B64_32


def test_value_and_file_variants_together_are_ambiguous(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = tmp_path / "pepper"
    secret.write_text("x", encoding="utf-8")
    monkeypatch.setenv("ARGUS_AUTH__API_KEY_PEPPER", "inline")
    monkeypatch.setenv("ARGUS_AUTH__API_KEY_PEPPER_FILE", str(secret))
    with pytest.raises(ConfigurationError, match="use exactly one"):
        load_settings(_env_file=None)


def test_unreadable_secret_file_is_a_configuration_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_SECURITY__SIGNING_KEY_FILE", "/definitely/missing/file")
    with pytest.raises(ConfigurationError, match="cannot read secret file"):
        load_settings(_env_file=None)


def test_nested_environment_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_WORKER__CONCURRENCY", "7")
    monkeypatch.setenv("ARGUS_HTTP__CORS_ORIGINS", '["https://app.example.com"]')
    settings = load_settings(_env_file=None)
    assert settings.worker.concurrency == 7
    assert settings.http.cors_origins == ("https://app.example.com",)


def test_redacted_summary_hides_every_secret() -> None:
    dumped = json.dumps(make_settings().redacted_summary())
    assert TEST_B64_32 not in dumped
    assert "BEGIN PRIVATE KEY" not in dumped
    assert "**********" in dumped


def test_unknown_nested_field_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match=r"database\.urll"):
        build_settings(_env_file=None, database={"urll": "x"})


def test_settings_are_immutable() -> None:
    settings: Settings = make_settings()
    with pytest.raises(ValueError, match="frozen"):
        settings.debug = True  # type: ignore[misc]
