"""API schemas of the security centre."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AfterValidator, Field

from argus.core.schemas import RequestModel, ResponseModel, StrictInt, clean_text

SwitchKindName = Literal["all", "agent", "tool", "provider", "model"]
Severity = Literal["critical", "high", "medium", "low"]


def _reason(value: str) -> str:
    value = " ".join(clean_text(value).split())
    if len(value) < 3:
        msg = "give a reason of at least 3 characters"
        raise ValueError(msg)
    return value


# ----------------------------------------------------------------------------- kill switches
class EngageKillSwitchRequest(RequestModel):
    kind: SwitchKindName
    target: Annotated[
        str, Field(min_length=1, max_length=64, pattern=r"^(\*|[a-z0-9][a-z0-9_.:/-]{0,63})$")
    ]
    """``*`` for every agent/tool/provider/model of that kind, or one name (lowercase)."""
    reason: Annotated[str, Field(max_length=500), AfterValidator(_reason)]
    expires_in_minutes: Annotated[StrictInt, Field(ge=5, le=43_200)] | None = None
    """Release automatically after this many minutes (5 minutes to 30 days); none = until
    released."""


class KillSwitchResponse(ResponseModel):
    id: UUID
    scope: Literal["organization", "platform"]
    kind: str
    target: str
    active: bool
    reason: str
    created_by: str
    created_at: datetime
    expires_at: datetime | None
    editable: bool
    """Platform-wide switches are set by the platform operator and cannot be changed here."""


# ---------------------------------------------------------------------------- audit integrity
class AuditVerificationResponse(ResponseModel):
    id: UUID
    verified_at: datetime
    trigger: str
    valid: bool
    events: int
    first_broken_seq: int | None
    reason: str | None
    duration_ms: int


# ------------------------------------------------------------------------------------ posture
class AccessSignals(ResponseModel):
    denied: int
    """Actions refused to members (permissions, role rules, policy)."""
    failed: int
    """Failed security-relevant actions (wrong MFA codes, failed API-key authentication...)."""
    api_key_failures: int


class AgentSignals(ResponseModel):
    tool_denials: int
    """Tool requests the runtime refused (undeclared, tainted, outside the allow-list)."""
    killed_tool_calls: int
    killed_runs: int


class ContentSignals(ResponseModel):
    injection_medium: int
    """Web pages and documents with a medium prompt-injection risk (wrapped with a warning)."""
    injection_high: int
    """Web pages and documents with a high risk (kept out of every model context)."""
    quarantined_documents: int


class EgressSignals(ResponseModel):
    blocked: int
    by_reason: dict[str, int]


class ModelSignals(ResponseModel):
    policy_blocks: int
    """Model calls refused by the data policy (e.g. confidential data to an external model)."""
    budget_blocks: int
    refusals: int


class CredentialSignals(ResponseModel):
    active_api_keys: int
    keys_without_expiry: int
    keys_expiring_soon: int
    stale_keys: int
    """Active keys unused for the stale period."""


class MemberSignals(ResponseModel):
    total: int
    owners: int
    admins: int
    require_mfa: bool


class Recommendation(ResponseModel):
    code: str
    severity: Severity
    message: str


class SecuritySummary(ResponseModel):
    window_days: int
    generated_at: datetime
    access: AccessSignals
    agents: AgentSignals
    content: ContentSignals
    egress: EgressSignals
    models: ModelSignals
    credentials: CredentialSignals
    members: MemberSignals
    kill_switches: list[KillSwitchResponse]
    last_audit_verification: AuditVerificationResponse | None
    recommendations: list[Recommendation]
