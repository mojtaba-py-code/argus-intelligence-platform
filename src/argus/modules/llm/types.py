"""Contracts between callers, the gateway and provider adapters.

Callers never build provider payloads. They hand the gateway a rendered, versioned prompt (trusted
text from the prompt registry), the user's own input already placed in that prompt, and any
retrieved or collected material as :class:`UntrustedData` parts. Adapters receive a
:class:`ProviderCall` in which untrusted parts are already wrapped in nonce-delimited blocks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel

from argus.core.classification import Classification
from argus.modules.llm.governance import Locality

Effort = Literal["low", "medium", "high", "xhigh", "max"]
Outcome = Literal[
    "ok",
    "refused",
    "error",
    "retryable_error",
    "invalid_output",
    "truncated",
    "blocked_policy",
    "blocked_budget",
    "circuit_open",
]


@dataclass(frozen=True)
class UntrustedData:
    """Retrieved or collected text. Rendered as data, never as instructions."""

    text: str
    label: str
    classification: Classification = Classification.PUBLIC


@dataclass(frozen=True)
class RenderedPrompt:
    name: str
    version: int
    sha256: str
    task: str
    system: str
    user: str
    output_schema: type[BaseModel] | None = None
    variables: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LLMRequest:
    prompt: RenderedPrompt
    untrusted: tuple[UntrustedData, ...] = ()
    classification: Classification = Classification.INTERNAL
    """Classification of the prompt's own inputs (the user's text); parts carry their own."""
    max_output_tokens: int | None = None
    effort: Effort | None = None

    @property
    def effective_classification(self) -> Classification:
        return max([self.classification, *(part.classification for part in self.untrusted)])


@dataclass(frozen=True)
class CallContext:
    """Who pays and under which policy: the accounting and governance scope of a call."""

    organization_id: UUID
    job_id: UUID | None = None
    agent_run_id: UUID | None = None
    approved_external: bool = False
    """An approval on the job allows sending data above the external ceiling (policy permitting)."""


@dataclass(frozen=True)
class ProviderCall:
    task: str
    model: str
    system: str
    user: str
    max_tokens: int
    output_model: type[BaseModel] | None
    effort: Effort | None
    refusal_fallback: bool
    variables: dict[str, Any]
    untrusted: tuple[UntrustedData, ...]


@dataclass(frozen=True)
class ProviderResult:
    text: str
    served_model: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    fallback_used: bool = False
    request_id: str | None = None


@dataclass(frozen=True)
class AttemptRecord:
    provider: str
    model: str
    outcome: Outcome
    error_code: str | None = None
    latency_ms: int = 0
    cost_usd: Decimal = Decimal(0)


@dataclass(frozen=True)
class LLMResult:
    text: str
    parsed: BaseModel | None
    provider: str
    model: str
    served_model: str
    locality: Locality
    input_tokens: int
    output_tokens: int
    cost_usd: Decimal
    latency_ms: int
    attempts: tuple[AttemptRecord, ...]
    fallback_used: bool = False


# ------------------------------------------------------------------------------- errors
class ProviderError(Exception):
    """Base class for adapter failures; ``code`` is recorded on the attempt."""

    code = "provider_error"
    retryable = False

    def __init__(self, detail: str = "", *, code: str | None = None) -> None:
        super().__init__(detail or self.code)
        if code:
            self.code = code


class ProviderRetryable(ProviderError):
    code = "retryable"
    retryable = True

    def __init__(
        self, detail: str = "", *, retry_after_s: float | None = None, code: str | None = None
    ) -> None:
        super().__init__(detail, code=code)
        self.retry_after_s = retry_after_s


class ProviderRefused(ProviderError):
    code = "refused"

    def __init__(self, category: str | None = None) -> None:
        super().__init__(f"refused ({category or 'unspecified'})")
        self.category = category


class ProviderTruncated(ProviderError):
    code = "truncated"


class ProviderUnsupported(ProviderError):
    """The provider cannot serve this task at all (e.g. no local implementation)."""

    code = "unsupported"


class LLMUnavailable(Exception):
    """No candidate could serve the request; ``attempts`` says why for each."""

    def __init__(self, task: str, attempts: tuple[AttemptRecord, ...], reason: str) -> None:
        super().__init__(f"no model could serve {task!r}: {reason}")
        self.task = task
        self.attempts = attempts
        self.reason = reason
