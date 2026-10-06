"""Application error hierarchy.

Every error carries a stable machine-readable ``code``, an HTTP-ish ``status`` and a **public**
``detail``. The detail is shown to clients, so it must be written for them: never include SQL,
file paths, provider names, stack traces, secrets or echoed input. Internal context goes into
``log_context`` (logged after redaction, never returned).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar


class ArgusError(Exception):
    """Base class. Subclasses set ``code``, ``status`` and ``title``."""

    code: ClassVar[str] = "internal_error"
    status: ClassVar[int] = 500
    title: ClassVar[str] = "Internal server error"
    default_detail: ClassVar[str] = "The request could not be completed."

    def __init__(
        self,
        detail: str | None = None,
        *,
        extensions: Mapping[str, Any] | None = None,
        log_context: Mapping[str, Any] | None = None,
    ) -> None:
        self.detail = detail or self.default_detail
        self.extensions: dict[str, Any] = dict(extensions or {})
        """Public, structured extra members of the problem document (e.g. ``retry_after``)."""
        self.log_context: dict[str, Any] = dict(log_context or {})
        """Private diagnostic context for logs only."""
        super().__init__(self.detail)


class ValidationFailed(ArgusError):
    code = "validation_failed"
    status = 422
    title = "Validation failed"
    default_detail = "The request is not valid."


class AuthenticationRequired(ArgusError):
    code = "authentication_required"
    status = 401
    title = "Authentication required"
    default_detail = "Valid credentials are required."


class InvalidCredentials(ArgusError):
    code = "invalid_credentials"
    status = 401
    title = "Invalid credentials"
    default_detail = "The credentials are not valid."


class PermissionDenied(ArgusError):
    code = "permission_denied"
    status = 403
    title = "Permission denied"
    default_detail = "You do not have permission to perform this action."


class NotFound(ArgusError):
    code = "not_found"
    status = 404
    title = "Not found"
    default_detail = "The resource does not exist or you do not have access to it."


class Conflict(ArgusError):
    code = "conflict"
    status = 409
    title = "Conflict"
    default_detail = "The request conflicts with the current state of the resource."


class Gone(ArgusError):
    code = "gone"
    status = 410
    title = "Gone"
    default_detail = "The resource is no longer available."


class PayloadTooLarge(ArgusError):
    code = "payload_too_large"
    status = 413
    title = "Payload too large"
    default_detail = "The request body exceeds the allowed size."


class UnsupportedMediaType(ArgusError):
    code = "unsupported_media_type"
    status = 415
    title = "Unsupported media type"
    default_detail = "This content type is not accepted."


class RateLimited(ArgusError):
    code = "rate_limited"
    status = 429
    title = "Too many requests"
    default_detail = "Rate limit exceeded. Retry later."

    def __init__(self, retry_after_s: float, detail: str | None = None) -> None:
        self.retry_after_s = max(0.0, retry_after_s)
        super().__init__(detail, extensions={"retry_after": round(self.retry_after_s, 3)})


class QuotaExceeded(ArgusError):
    code = "quota_exceeded"
    status = 403
    title = "Quota exceeded"
    default_detail = "Your organisation's plan limit for this action has been reached."


class BudgetExceeded(ArgusError):
    code = "budget_exceeded"
    status = 402
    title = "Budget exceeded"
    default_detail = "The cost budget for this operation has been exhausted."


class PolicyViolation(ArgusError):
    """A request was refused by a security or data-governance policy (not by permissions)."""

    code = "policy_violation"
    status = 403
    title = "Refused by policy"
    default_detail = "The request was refused by a security policy."


class ServiceUnavailable(ArgusError):
    code = "service_unavailable"
    status = 503
    title = "Service unavailable"
    default_detail = "The service is temporarily unavailable. Retry later."


class UpstreamError(ArgusError):
    code = "upstream_error"
    status = 502
    title = "Upstream error"
    default_detail = "A dependency failed to respond correctly."


class RequestTimeout(ArgusError):
    code = "timeout"
    status = 504
    title = "Timeout"
    default_detail = "The request took too long to complete."
