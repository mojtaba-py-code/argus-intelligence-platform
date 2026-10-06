"""Typed, validated configuration.

Every setting comes from ``ARGUS_*`` environment variables (nested sections use ``__``), from a
``.env`` file in development, or from ``ARGUS_..._FILE`` variables that point at secret files
(Docker / Kubernetes secrets). Three properties matter more than convenience:

* **Typos fail loudly** - an unknown ``ARGUS_`` variable is an error with a suggestion, so a
  misspelt security setting can never silently fall back to its default.
* **Secrets never print** - secret values are :class:`pydantic.SecretStr`.
* **Production refuses insecure configuration** - :meth:`Settings._production_guards` lists every
  rule; the process does not start when one is violated.
"""

from __future__ import annotations

import difflib
import json
import os
from collections.abc import Mapping
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import (
    BaseSettings,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

ENV_PREFIX = "ARGUS_"
NESTED_DELIMITER = "__"
FILE_SUFFIX = "_FILE"
_MAX_SECRET_FILE_BYTES = 64 * 1024

DEV_DATABASE_URL = "postgresql+asyncpg://argus_app:argus_app_dev_password@localhost:5432/argus"


class ConfigurationError(ValueError):
    """Raised when configuration is missing, malformed or unsafe for the environment."""


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"

    @property
    def is_production_like(self) -> bool:
        """Staging must behave exactly like production, including every safety guard."""
        return self in {Environment.STAGING, Environment.PRODUCTION}


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DatabaseSettings(_Section):
    url: SecretStr = SecretStr(DEV_DATABASE_URL)
    """DSN of the **runtime** role (no DDL, no BYPASSRLS)."""
    migration_url: SecretStr | None = None
    """DSN of the **owner** role used only by ``argus db migrate``."""
    app_role: str = Field("argus_app", pattern=r"^[a-z_][a-z0-9_]{0,62}$")
    """Role that migrations GRANT runtime privileges to (must match the role in ``url``)."""
    pool_size: int = Field(10, ge=1, le=200)
    max_overflow: int = Field(10, ge=0, le=200)
    pool_timeout_s: float = Field(10.0, gt=0, le=120)
    pool_recycle_s: int = Field(1800, ge=60)
    statement_timeout_ms: int = Field(30_000, ge=100, le=3_600_000)
    lock_timeout_ms: int = Field(5_000, ge=100, le=600_000)
    idle_in_transaction_timeout_ms: int = Field(60_000, ge=1_000, le=3_600_000)
    tls_mode: Literal["disable", "prefer", "require", "verify-full"] = "prefer"
    echo: bool = False


class RedisSettings(_Section):
    url: SecretStr | None = None
    """``redis://`` or ``rediss://`` URL. Optional in development (in-process fallbacks)."""
    key_prefix: str = Field("argus", pattern=r"^[a-z][a-z0-9_-]{0,31}$")
    socket_timeout_s: float = Field(2.0, gt=0, le=30)


class HTTPSettings(_Section):
    public_base_url: AnyHttpUrl = AnyHttpUrl("http://localhost:8000")
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "testserver")
    cors_origins: tuple[str, ...] = ()
    trusted_proxies: tuple[IPv4Network | IPv6Network, ...] = ()
    """Peers whose ``X-Forwarded-For`` / ``X-Forwarded-Proto`` headers are believed."""
    max_body_bytes: int = Field(1 * 1024 * 1024, ge=1024, le=64 * 1024 * 1024)
    max_upload_bytes: int = Field(25 * 1024 * 1024, ge=1024, le=512 * 1024 * 1024)
    request_timeout_s: float = Field(30.0, gt=0, le=600)
    expose_docs: bool = True
    web_dashboard: bool = True
    """Serve the web dashboard at ``/app`` (static files; it uses the public API)."""
    hsts: bool = False
    """Send ``Strict-Transport-Security``. Always on in production."""
    problem_type_base: str = "urn:argus:problem:"


class AuthSettings(_Section):
    issuer: str = "argus"
    audience: str = "argus-api"
    access_token_ttl_s: int = Field(600, ge=60, le=3600)
    refresh_token_ttl_s: int = Field(7 * 24 * 3600, ge=3600, le=90 * 24 * 3600)
    session_max_age_s: int = Field(30 * 24 * 3600, ge=3600, le=365 * 24 * 3600)
    jwt_signing_keys: SecretStr | None = None
    """JSON object ``{"<kid>": "<Ed25519 PKCS#8 PEM>", ...}``."""
    jwt_active_kid: str | None = None
    api_key_pepper: SecretStr | None = None
    """Base64 secret (>= 32 bytes) used to HMAC API-key secrets."""
    require_email_verification: bool = True
    email_verification_ttl_s: int = Field(48 * 3600, ge=600)
    password_reset_ttl_s: int = Field(30 * 60, ge=300, le=24 * 3600)
    mfa_challenge_ttl_s: int = Field(5 * 60, ge=60, le=900)
    mfa_max_attempts: int = Field(5, ge=1, le=20)
    lockout_threshold: int = Field(5, ge=3, le=50)
    lockout_base_s: int = Field(60, ge=1)
    lockout_max_s: int = Field(900, ge=60)
    invitation_ttl_s: int = Field(7 * 24 * 3600, ge=3600)


class SecuritySettings(_Section):
    encryption_keys: SecretStr | None = None
    """JSON object ``{"<key id>": "<base64 32-byte AES key>", ...}``."""
    active_encryption_key: str | None = None
    audit_hmac_key: SecretStr | None = None
    signing_key: SecretStr | None = None
    """Base64 HMAC key for signed download URLs."""
    allow_plaintext_internal_traffic: bool = False
    """Explicit, logged acceptance of unencrypted PostgreSQL/Redis traffic in production."""
    injection_block_threshold: float = Field(0.8, ge=0, le=1)
    injection_flag_threshold: float = Field(0.4, ge=0, le=1)
    audit_verify_interval_h: int = Field(24, ge=1, le=720)
    """Every organisation's audit chain is re-verified at least this often."""
    audit_verify_check_s: int = Field(900, ge=60, le=86_400)
    """How often the scheduler looks for organisations due a verification."""
    audit_verify_batch: int = Field(25, ge=1, le=1000)
    """Organisations verified per scheduler pass."""
    audit_verification_retention_days: int = Field(90, ge=7, le=3650)


class EgressSettings(_Section):
    user_agent: str = (
        "ArgusResearchBot/0.1 (+https://github.com/mojtaba-py-code/argus-intelligence-platform)"
    )
    connect_timeout_s: float = Field(5.0, gt=0, le=60)
    read_timeout_s: float = Field(15.0, gt=0, le=120)
    total_timeout_s: float = Field(30.0, gt=0, le=300)
    max_redirects: int = Field(5, ge=0, le=10)
    max_response_bytes: int = Field(10 * 1024 * 1024, ge=1024, le=200 * 1024 * 1024)
    max_decompression_ratio: int = Field(100, ge=1, le=1000)
    allowed_ports: tuple[int, ...] = (80, 443)
    respect_robots_txt: bool = True
    per_domain_interval_s: float = Field(2.0, ge=0, le=120)
    max_concurrent_fetches: int = Field(4, ge=1, le=64)
    """Pages fetched at once per research job (per-host politeness still applies). Each fetch
    briefly holds a database connection: keep worker.concurrency x this below the pool size."""


class LLMSettings(_Section):
    routing_file: Path | None = None
    """YAML routing table (models, localities, prices, routes); defaults to the packaged
    ``configs/llm_routing.yaml``. OpenAI-compatible models are declared there as ``openai/<id>``."""
    prompts_dir: Path | None = None
    """Prompt registry directory; defaults to the packaged ``prompts/``."""
    anthropic_api_key: SecretStr | None = None
    anthropic_base_url: AnyHttpUrl | None = None
    anthropic_refusal_fallback: bool = True
    openai_api_key: SecretStr | None = None
    openai_base_url: AnyHttpUrl | None = None
    request_timeout_s: float = Field(180.0, gt=0, le=1800)
    max_retries_per_model: int = Field(2, ge=0, le=6)
    breaker_failure_threshold: int = Field(5, ge=1, le=100)
    breaker_reset_s: float = Field(60.0, gt=0, le=3600)
    default_job_budget_usd: float = Field(5.0, gt=0, le=10_000)


class EmbeddingSettings(_Section):
    """Vectors are 1024-dimensional (fixed by the ``document_chunks`` schema).

    ``local`` is a deterministic hashing embedder - offline, free, lexical-semantic quality.
    ``voyage`` (Voyage AI) gives real semantic quality; text above an organisation's
    external-processing ceiling is never sent to it and stays keyword-searchable only.
    """

    provider: Literal["local", "voyage"] = "local"
    model: str | None = None
    """Voyage model (default ``voyage-4``); the local embedder is always ``argus-hash-v1``."""
    voyage_api_key: SecretStr | None = None
    batch_size: int = Field(64, ge=1, le=1000)
    request_timeout_s: float = Field(60.0, gt=0, le=600)

    @model_validator(mode="after")
    def _provider_requirements(self) -> EmbeddingSettings:
        if self.provider == "voyage" and self.voyage_api_key is None:
            msg = "embeddings provider 'voyage' requires embeddings.voyage_api_key"
            raise ValueError(msg)
        return self


class RetrievalSettings(_Section):
    """Chunking and hybrid retrieval (ADR 0004)."""

    chunk_chars: int = Field(1200, ge=200, le=8000)
    chunk_overlap_chars: int = Field(180, ge=0, le=2000)
    candidates: int = Field(40, ge=5, le=500)
    """Candidates fetched by *each* of the vector and keyword searches before fusion."""
    rrf_k: int = Field(60, ge=1, le=1000)
    per_document_cap: int = Field(3, ge=1, le=50)
    exclude_injection_levels: tuple[Literal["low", "medium", "high"], ...] = ("high",)
    rerank: Literal["none", "lexical", "voyage"] = "lexical"
    cache_ttl_s: int = Field(600, ge=0, le=86_400)
    hnsw_ef_search: int = Field(100, ge=10, le=1000)
    keyword_rank_limit: int = Field(20_000, ge=1_000, le=1_000_000)
    """Most keyword matches ranked per search. A query whose terms appear in more chunks than
    this ranks only that many (the vector branch still covers the corpus): it bounds the cost of
    very unspecific queries on large projects."""

    @model_validator(mode="after")
    def _overlap_below_window(self) -> RetrievalSettings:
        if self.chunk_overlap_chars * 2 > self.chunk_chars:
            msg = "retrieval.chunk_overlap_chars must be at most half of retrieval.chunk_chars"
            raise ValueError(msg)
        return self


class SearchSettings(_Section):
    provider: Literal["none", "brave", "searxng", "static"] = "none"
    brave_api_key: SecretStr | None = None
    searxng_url: AnyHttpUrl | None = None
    static_results_file: Path | None = None
    max_results_per_query: int = Field(8, ge=1, le=50)
    concurrency: int = Field(2, ge=1, le=16)
    """Searches in flight per research job (respect your provider plan's request rate)."""

    @model_validator(mode="after")
    def _provider_requirements(self) -> SearchSettings:
        # Fail at startup rather than silently running research without search.
        required = {
            "brave": ("brave_api_key", self.brave_api_key),
            "searxng": ("searxng_url", self.searxng_url),
            "static": ("static_results_file", self.static_results_file),
        }
        if self.provider in required and required[self.provider][1] is None:
            msg = f"search provider {self.provider!r} requires search.{required[self.provider][0]}"
            raise ValueError(msg)
        return self


class StorageSettings(_Section):
    """Blob storage. Objects are encrypted by the application before they reach either backend."""

    backend: Literal["local", "s3"] = "local"
    local_root: Path = Path("var/storage")
    s3_bucket: str | None = None
    s3_endpoint_url: AnyHttpUrl | None = None
    """For S3-compatible services (MinIO, Ceph, R2); leave unset for AWS."""
    s3_region: str | None = None
    s3_access_key_id: SecretStr | None = None
    """Leave both keys unset to use the default AWS credential chain (instance/IRSA roles)."""
    s3_secret_access_key: SecretStr | None = None
    s3_server_side_encryption: Literal["AES256", "aws:kms"] | None = None
    """Optional extra layer: the bucket encrypts the (already encrypted) objects again."""
    signed_url_ttl_s: int = Field(300, ge=30, le=3600)

    @model_validator(mode="after")
    def _backend_requirements(self) -> StorageSettings:
        if self.backend == "s3" and not self.s3_bucket:
            msg = "storage backend 's3' requires storage.s3_bucket"
            raise ValueError(msg)
        if (self.s3_access_key_id is None) != (self.s3_secret_access_key is None):
            msg = "set both storage.s3_access_key_id and storage.s3_secret_access_key, or neither"
            raise ValueError(msg)
        return self


class DocumentSettings(_Section):
    """Limits for untrusted documents (uploads and binary web content).

    The upload size limit itself is ``http.max_upload_bytes`` (enforced while the body streams in).
    """

    max_pdf_pages: int = Field(2000, ge=1, le=20_000)
    max_archive_entries: int = Field(1000, ge=10, le=100_000)
    max_uncompressed_bytes: int = Field(100 * 1024 * 1024, ge=1024 * 1024, le=2 * 1024**3)
    max_compression_ratio: int = Field(100, ge=10, le=10_000)
    max_json_depth: int = Field(64, ge=4, le=512)
    max_csv_field_bytes: int = Field(1024 * 1024, ge=1024, le=64 * 1024 * 1024)
    max_csv_rows: int = Field(200_000, ge=100, le=10_000_000)
    max_text_chars: int = Field(5_000_000, ge=10_000, le=50_000_000)
    parse_timeout_s: float = Field(60.0, gt=0, le=600)
    parse_memory_mb: int = Field(768, ge=128, le=16_384)
    """Address-space limit of the parser sandbox (POSIX; Windows relies on the timeout)."""
    scanner: Literal["signature", "clamav"] = "signature"
    """``signature`` only recognises the EICAR test file - development and CI only."""
    clamav_host: str = "clamav"
    clamav_port: int = Field(3310, ge=1, le=65535)
    clamav_timeout_s: float = Field(60.0, gt=0, le=600)


class EmailSettings(_Section):
    backend: Literal["memory", "console", "smtp"] = "console"
    from_address: str = "Argus <no-reply@argus.local>"
    smtp_host: str | None = None
    smtp_port: int = Field(587, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_starttls: bool = True
    app_base_url: AnyHttpUrl = AnyHttpUrl("http://localhost:3000")
    """Front-end URL used in e-mail links; tokens travel in the URL *fragment*."""


class ObservabilitySettings(_Section):
    service_name: str = "argus"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "json"
    otel_enabled: bool = False
    otel_endpoint: AnyHttpUrl | None = None
    """OTLP/HTTP collector base URL (``/v1/traces`` is appended)."""
    otel_headers: SecretStr | None = None
    """Extra exporter headers, ``name=value`` pairs separated by commas (collector auth)."""
    otel_sample_ratio: float = Field(0.1, ge=0, le=1)
    """Share of new traces kept; child spans follow their parent's decision."""
    trust_incoming_trace_context: bool = False
    """Continue a caller's ``traceparent``. Only behind a gateway that sets the header itself."""
    metrics_enabled: bool = True
    metrics_token: SecretStr | None = None
    """Bearer token required on ``/metrics`` (Prometheus scrape). Required in production."""
    metrics_port: int | None = Field(None, ge=1024, le=65535)
    """Worker and scheduler processes serve ``/metrics`` on this port when set."""
    metrics_host: str = "127.0.0.1"
    """Bind address of that endpoint (``0.0.0.0`` inside a container, behind network policy)."""


class WorkerSettings(_Section):
    queues: tuple[str, ...] = ("default", "research", "documents", "monitoring")
    concurrency: int = Field(4, ge=1, le=256)
    lease_s: int = Field(60, ge=10, le=3600)
    heartbeat_s: int = Field(15, ge=1, le=600)
    poll_interval_s: float = Field(2.0, gt=0, le=60)
    shutdown_grace_s: float = Field(30.0, ge=0, le=600)


class ResearchSettings(_Section):
    max_objective_chars: int = Field(4000, ge=100, le=20_000)
    max_sources_per_job: int = Field(40, ge=1, le=500)
    max_queries_per_job: int = Field(12, ge=1, le=100)
    approval_cost_threshold_usd: float = Field(20.0, gt=0)
    job_timeout_s: int = Field(45 * 60, ge=60, le=24 * 3600)


class MonitoringSettings(_Section):
    dispatch_interval_s: int = Field(60, ge=10, le=3600)
    """How often the scheduler looks for due monitors."""
    dispatch_batch: int = Field(50, ge=1, le=1000)
    max_monitors_per_org: int = Field(50, ge=1, le=10_000)
    max_targets: int = Field(20, ge=1, le=100)
    max_queries: int = Field(5, ge=1, le=20)
    results_per_query: int = Field(5, ge=1, le=20)
    max_assessed_changes: int = Field(10, ge=0, le=100)
    """Changes per run that may be judged by a model (the rest are scored by code only)."""
    assessment_floor: float = Field(0.2, ge=0, le=1)
    """Below this code score a change is recorded but never sent to a model or alerted."""


class NotificationSettings(_Section):
    email: bool = True
    """Send e-mail notifications where an event asks for them."""
    retention_days: int = Field(180, ge=7, le=3650)
    """Read notifications older than this are deleted by the scheduler."""


class PlatformSettings(_Section):
    """SaaS operation: plans, organisation lifecycle, exports and platform-wide retention."""

    default_plan: Literal["free", "team", "business", "enterprise"] = "enterprise"
    """Plan of new organisations. Self-hosted installations keep "enterprise" (no quotas);
    a hosted service sets "free" and upgrades organisations with ``argus orgs set-plan``."""
    deletion_grace_days: int = Field(30, ge=1, le=365)
    """How long a deleted organisation can still be restored before it is purged."""
    export_ttl_days: int = Field(7, ge=1, le=90)
    export_max_document_bytes: int = Field(128 * 1024 * 1024, ge=0, le=1024**3)
    """Original documents are included in an export up to this total; beyond it the export
    lists them (each stays downloadable on its own). Building and downloading an archive takes a
    few times its size in memory, in the worker and in the API: size both before raising it."""
    llm_requests_retention_days: int = Field(400, ge=30, le=3650)
    """Per-call model ledger rows (daily aggregates are kept for budgets and reporting)."""
    finished_jobs_retention_days: int = Field(30, ge=1, le=3650)
    platform_audit_retention_days: int = Field(730, ge=365, le=3650)
    """Platform audit chain (sign-ins), pruned by ``argus audit prune`` with a checkpoint."""


class ReportSettings(_Section):
    pdf_font_path: Path | None = None
    """A TrueType font covering the scripts your reports use (the container ships DejaVu Sans).
    Without one, PDF exports use a Latin-1 core font and replace other characters."""
    revision_threshold: float = Field(0.8, ge=0, le=1)
    """Below this mechanical score (references, grounding, balance) a draft gets one revision."""


class Settings(BaseSettings):
    """Root configuration object. Construct once per process and pass it explicitly."""

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        env_nested_delimiter=NESTED_DELIMITER,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="forbid",
        frozen=True,
        case_sensitive=False,
        validate_default=True,
    )

    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False
    database: DatabaseSettings = DatabaseSettings()
    redis: RedisSettings = RedisSettings()
    http: HTTPSettings = HTTPSettings()
    auth: AuthSettings = AuthSettings()
    security: SecuritySettings = SecuritySettings()
    egress: EgressSettings = EgressSettings()
    llm: LLMSettings = LLMSettings()
    embeddings: EmbeddingSettings = EmbeddingSettings()
    retrieval: RetrievalSettings = RetrievalSettings()
    search: SearchSettings = SearchSettings()
    storage: StorageSettings = StorageSettings()
    documents: DocumentSettings = DocumentSettings()
    email: EmailSettings = EmailSettings()
    observability: ObservabilitySettings = ObservabilitySettings()
    worker: WorkerSettings = WorkerSettings()
    research: ResearchSettings = ResearchSettings()
    reports: ReportSettings = ReportSettings()
    monitoring: MonitoringSettings = MonitoringSettings()
    notifications: NotificationSettings = NotificationSettings()
    platform: PlatformSettings = PlatformSettings()

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        del file_secret_settings, env_settings  # replaced: see the two custom sources below
        return (
            init_settings,
            _EnvWithoutFileReferences(settings_cls),
            _FileSecretsSource(settings_cls),
            dotenv_settings,
        )

    @field_validator("http", mode="after")
    @classmethod
    def _http_sane(cls, value: HTTPSettings) -> HTTPSettings:
        for host in value.allowed_hosts:
            if not host or any(ch.isspace() for ch in host):
                raise ConfigurationError("http.allowed_hosts contains an empty or blank entry")
        return value

    @model_validator(mode="after")
    def _cross_section_requirements(self) -> Self:
        if self.retrieval.rerank == "voyage" and self.embeddings.voyage_api_key is None:
            raise ConfigurationError("retrieval.rerank 'voyage' requires embeddings.voyage_api_key")
        return self

    @model_validator(mode="after")
    def _production_guards(self) -> Self:
        if not self.environment.is_production_like:
            return self
        problems = list(_production_problems(self))
        if problems:
            joined = "\n  - ".join(problems)
            raise ConfigurationError(
                f"refusing to start in {self.environment.value}: insecure configuration\n  - {joined}"
            )
        return self

    def redacted_summary(self) -> dict[str, Any]:
        """Configuration as a dict with every secret replaced - safe to print or log."""
        summary: dict[str, Any] = json.loads(self.model_dump_json())  # SecretStr -> '**********'
        return summary


def _production_problems(settings: Settings) -> list[str]:
    """Every rule production enforces. Each returned string names the variable to fix."""
    problems: list[str] = []
    http, auth, sec = settings.http, settings.auth, settings.security
    if settings.debug:
        problems.append("ARGUS_DEBUG must be false")
    if http.expose_docs:
        problems.append("ARGUS_HTTP__EXPOSE_DOCS must be false (no public OpenAPI UI)")
    if "*" in http.cors_origins:
        problems.append("ARGUS_HTTP__CORS_ORIGINS must list explicit origins, not '*'")
    if "*" in http.allowed_hosts:
        problems.append("ARGUS_HTTP__ALLOWED_HOSTS must list explicit host names, not '*'")
    if http.public_base_url.scheme != "https":
        problems.append("ARGUS_HTTP__PUBLIC_BASE_URL must use https")
    if settings.database.echo:
        problems.append("ARGUS_DATABASE__ECHO must be false (SQL echo can log sensitive values)")
    if settings.database.url.get_secret_value() == DEV_DATABASE_URL:
        problems.append("ARGUS_DATABASE__URL still has the development default")
    # The owner DSN is optional here on purpose: API, worker and scheduler processes must not
    # hold credentials that can change the schema. Operator commands that need it (migrations,
    # audit verification and export, platform kill switches) require it themselves.
    if (
        settings.database.migration_url is not None
        and settings.database.migration_url.get_secret_value()
        == settings.database.url.get_secret_value()
    ):
        problems.append("ARGUS_DATABASE__MIGRATION_URL must differ from the runtime role DSN")
    if settings.redis.url is None:
        problems.append("ARGUS_REDIS__URL is required (shared rate limits and revocation cache)")
    if not sec.allow_plaintext_internal_traffic:
        if settings.database.tls_mode not in {"require", "verify-full"}:
            problems.append(
                "ARGUS_DATABASE__TLS_MODE must be require/verify-full "
                "(or accept the risk with ARGUS_SECURITY__ALLOW_PLAINTEXT_INTERNAL_TRAFFIC=true)"
            )
        redis_url = settings.redis.url.get_secret_value() if settings.redis.url else ""
        if redis_url and not redis_url.startswith("rediss://"):
            problems.append(
                "ARGUS_REDIS__URL must use rediss:// "
                "(or accept the risk with ARGUS_SECURITY__ALLOW_PLAINTEXT_INTERNAL_TRAFFIC=true)"
            )
    if auth.jwt_signing_keys is None or not auth.jwt_active_kid:
        problems.append("ARGUS_AUTH__JWT_SIGNING_KEYS and ARGUS_AUTH__JWT_ACTIVE_KID are required")
    for name, secret in (
        ("ARGUS_AUTH__API_KEY_PEPPER", auth.api_key_pepper),
        ("ARGUS_SECURITY__AUDIT_HMAC_KEY", sec.audit_hmac_key),
        ("ARGUS_SECURITY__SIGNING_KEY", sec.signing_key),
    ):
        if secret is None or len(secret.get_secret_value()) < 43:  # base64 of >= 32 bytes
            problems.append(f"{name} must be a base64 secret of at least 32 bytes")
    if sec.encryption_keys is None or not sec.active_encryption_key:
        problems.append(
            "ARGUS_SECURITY__ENCRYPTION_KEYS and ARGUS_SECURITY__ACTIVE_ENCRYPTION_KEY are required"
        )
    if settings.documents.scanner != "clamav":
        problems.append(
            "ARGUS_DOCUMENTS__SCANNER must be clamav "
            "(the signature scanner only recognises the EICAR test file)"
        )
    if settings.email.backend != "smtp":
        problems.append(
            "ARGUS_EMAIL__BACKEND must be smtp (the console backend prints links that carry tokens)"
        )
    obs = settings.observability
    if obs.metrics_enabled and obs.metrics_token is None:
        problems.append("ARGUS_OBSERVABILITY__METRICS_TOKEN is required when metrics are enabled")
    if obs.otel_enabled and obs.otel_endpoint is None:
        problems.append("ARGUS_OBSERVABILITY__OTEL_ENDPOINT is required when tracing is enabled")
    if (
        obs.otel_endpoint is not None
        and obs.otel_endpoint.scheme != "https"
        and not sec.allow_plaintext_internal_traffic
    ):
        problems.append(
            "ARGUS_OBSERVABILITY__OTEL_ENDPOINT must use https "
            "(or accept the risk with ARGUS_SECURITY__ALLOW_PLAINTEXT_INTERNAL_TRAFFIC=true)"
        )
    if obs.log_level == "DEBUG":
        problems.append("ARGUS_OBSERVABILITY__LOG_LEVEL must not be DEBUG")
    return problems


class _EnvWithoutFileReferences(EnvSettingsSource):
    """The standard environment source, minus ``*_FILE`` references (read by the source below).

    Without this filter, ``ARGUS_AUTH__API_KEY_PEPPER_FILE`` would be exploded into a nested
    ``auth.api_key_pepper_file`` field and rejected as unknown.
    """

    def _load_env_vars(self) -> Mapping[str, str | None]:
        loaded = super()._load_env_vars()
        return {key: value for key, value in loaded.items() if not key.lower().endswith("_file")}


class _FileSecretsSource(PydanticBaseSettingsSource):
    """Reads ``ARGUS_<PATH>_FILE=/run/secrets/x`` variables (the Docker/Kubernetes convention).

    Setting both ``ARGUS_X`` and ``ARGUS_X_FILE`` is an error: ambiguity in secret sourcing is how
    a rotated secret silently keeps its old value.
    """

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        del field  # unused: __call__ builds the whole mapping
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        environ = {key.upper(): value for key, value in os.environ.items()}
        for key, path_value in environ.items():
            if not (key.startswith(ENV_PREFIX) and key.endswith(FILE_SUFFIX)):
                continue
            plain_key = key[: -len(FILE_SUFFIX)]
            if plain_key in environ:
                raise ConfigurationError(f"both {plain_key} and {key} are set; use exactly one")
            path = Path(path_value)
            try:
                with path.open("rb") as handle:
                    raw = handle.read(_MAX_SECRET_FILE_BYTES + 1)
            except OSError as exc:
                raise ConfigurationError(
                    f"{key}: cannot read secret file ({exc.strerror})"
                ) from exc
            if len(raw) > _MAX_SECRET_FILE_BYTES:
                raise ConfigurationError(f"{key}: secret file larger than 64 KiB")
            value = raw.decode("utf-8").strip()
            parts = plain_key[len(ENV_PREFIX) :].lower().split(NESTED_DELIMITER)
            cursor = result
            for part in parts[:-1]:
                cursor = cursor.setdefault(part, {})
            cursor[parts[-1]] = value
        return result


def _known_variables() -> set[str]:
    names: set[str] = set()
    for field_name, field in Settings.model_fields.items():
        annotation = field.annotation
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            for sub_name in annotation.model_fields:
                names.add(f"{ENV_PREFIX}{field_name}{NESTED_DELIMITER}{sub_name}".upper())
        else:
            names.add(f"{ENV_PREFIX}{field_name}".upper())
    return names


def check_unknown_variables(environ: dict[str, str] | None = None) -> None:
    """Raise if an ``ARGUS_*`` variable does not correspond to a setting (typo protection)."""
    environ = dict(os.environ) if environ is None else environ
    known = _known_variables()
    unknown: list[str] = []
    for raw_key in environ:
        key = raw_key.upper()
        if not key.startswith(ENV_PREFIX) or key.startswith(f"{ENV_PREFIX}TEST_"):
            continue  # ARGUS_TEST_* belong to the test suite, not to Settings
        base = key.removesuffix(FILE_SUFFIX)
        if base not in known:
            hint = difflib.get_close_matches(base, sorted(known), n=1)
            unknown.append(f"{raw_key}" + (f" (did you mean {hint[0]}?)" if hint else ""))
    if unknown:
        raise ConfigurationError("unknown configuration variables: " + ", ".join(sorted(unknown)))


def build_settings(**values: Any) -> Settings:
    """Construct :class:`Settings`, converting validation failures into a *sanitised*
    :class:`ConfigurationError`.

    Pydantic's own message embeds the offending input (``input_value=...``), which for settings
    means secrets and DSNs ending up in terminals, CI logs and crash reports. Only field locations
    and messages are kept.
    """
    try:
        return Settings(**values)
    except ValidationError as exc:
        lines = []
        for error in exc.errors(include_input=False, include_url=False, include_context=False):
            location = ".".join(str(part) for part in error.get("loc", ())) or "settings"
            message = str(error.get("msg", "invalid value")).removeprefix("Value error, ")
            lines.append(f"{location}: {message}")
        raise ConfigurationError("\n".join(lines)) from None


def load_settings(**overrides: Any) -> Settings:
    """Load settings from the environment, rejecting unknown ``ARGUS_*`` variables first."""
    check_unknown_variables()
    return build_settings(**overrides)
