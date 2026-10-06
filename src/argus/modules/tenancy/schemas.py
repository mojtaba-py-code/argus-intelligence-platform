"""Tenancy request/response models and the organisation settings document."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator

from argus.core.classification import Classification
from argus.core.schemas import LongText, Name, RequestModel, ResponseModel, StrictBool, StrictInt
from argus.modules.identity.schemas import Email
from argus.security.permissions import API_KEY_SCOPES, OrgRole, Permission, ProjectRole

_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$")
RESERVED_SLUGS = frozenset(
    {
        "admin",
        "api",
        "app",
        "argus",
        "auth",
        "billing",
        "docs",
        "help",
        "internal",
        "login",
        "platform",
        "root",
        "security",
        "status",
        "support",
        "system",
        "www",
    }
)


def _slug(value: str) -> str:
    value = value.strip().lower()
    if not _SLUG.fullmatch(value) or "--" in value:
        msg = "3-48 characters: lower-case letters, digits and single hyphens"
        raise ValueError(msg)
    if value in RESERVED_SLUGS:
        msg = "this slug is reserved"
        raise ValueError(msg)
    return value


Slug = Annotated[str, AfterValidator(_slug)]


# ------------------------------------------------------------------- organisation settings
class DataPolicy(BaseModel):
    """Highest classification each provider locality may receive (see ADR 0006)."""

    model_config = ConfigDict(extra="forbid")

    external: Classification = Classification.INTERNAL
    self_hosted: Classification = Classification.CONFIDENTIAL
    local: Classification = Classification.RESTRICTED
    external_above_ceiling: Literal["approval", "never"] = "approval"


class Budgets(BaseModel):
    model_config = ConfigDict(extra="forbid")

    monthly_llm_usd: float = Field(100.0, ge=0, le=1_000_000)
    job_default_usd: float = Field(5.0, gt=0, le=10_000)
    approval_threshold_usd: float = Field(20.0, gt=0, le=100_000)


class Retention(BaseModel):
    model_config = ConfigDict(extra="forbid")

    raw_snapshots_days: int = Field(90, ge=1, le=3650)
    monitor_snapshots_days: int = Field(180, ge=1, le=3650)
    audit_days: int = Field(365, ge=90, le=3650)


class OrganizationSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    require_mfa: bool = False
    data_policy: DataPolicy = DataPolicy()
    budgets: Budgets = Budgets()
    retention: Retention = Retention()
    default_document_classification: Classification = Classification.CONFIDENTIAL


# ------------------------------------------------------------------------- organisations
class CreateOrganizationRequest(RequestModel):
    name: Name
    slug: Slug | None = None


class UpdateOrganizationRequest(RequestModel):
    name: Name | None = None
    require_mfa: StrictBool | None = None
    data_policy: DataPolicy | None = None
    budgets: Budgets | None = None
    retention: Retention | None = None


class OrganizationResponse(ResponseModel):
    id: UUID
    name: str
    slug: str
    status: str
    plan: str
    created_at: datetime
    role: OrgRole | None = None
    settings: OrganizationSettings | None = None


# ------------------------------------------------------------------------------ members
class MemberResponse(ResponseModel):
    user_id: UUID
    email: str
    full_name: str
    role: OrgRole
    joined_at: datetime


class ChangeRoleRequest(RequestModel):
    role: OrgRole


class CreateInvitationRequest(RequestModel):
    email: Email
    role: OrgRole = OrgRole.ANALYST


class InvitationResponse(ResponseModel):
    id: UUID
    email: str
    role: OrgRole
    created_at: datetime
    expires_at: datetime
    accepted_at: datetime | None
    revoked_at: datetime | None


class AcceptInvitationRequest(RequestModel):
    token: Annotated[str, Field(min_length=16, max_length=512, pattern=r"^[A-Za-z0-9_\-]+$")]


# ----------------------------------------------------------------------------- projects
class CreateProjectRequest(RequestModel):
    name: Name
    description: LongText = ""
    visibility: Literal["organization", "restricted"] = "organization"


class UpdateProjectRequest(RequestModel):
    name: Name | None = None
    description: LongText | None = None
    visibility: Literal["organization", "restricted"] | None = None
    archived: StrictBool | None = None


class ProjectResponse(ResponseModel):
    id: UUID
    organization_id: UUID
    name: str
    description: str
    visibility: str
    created_at: datetime
    updated_at: datetime
    archived_at: datetime | None


class ProjectMemberRequest(RequestModel):
    role: ProjectRole


class ProjectMemberResponse(ResponseModel):
    user_id: UUID
    role: ProjectRole
    added_at: datetime


# ------------------------------------------------------------- service accounts and keys
class CreateServiceAccountRequest(RequestModel):
    name: Annotated[str, Field(min_length=3, max_length=100, pattern=r"^[a-z0-9][a-z0-9_-]+$")]
    description: LongText = ""
    role: Literal["admin", "analyst", "viewer"] = "viewer"


class ServiceAccountResponse(ResponseModel):
    id: UUID
    name: str
    description: str
    role: OrgRole
    created_at: datetime
    disabled_at: datetime | None


class CreateApiKeyRequest(RequestModel):
    name: Annotated[str, Field(min_length=1, max_length=100)]
    scopes: list[Permission] = Field(min_length=1, max_length=len(Permission))
    service_account_id: UUID | None = None
    expires_in_days: StrictInt | None = Field(90, ge=1, le=365)

    @field_validator("scopes")
    @classmethod
    def _allowed_scopes(cls, value: list[Permission]) -> list[Permission]:
        forbidden = sorted(p.value for p in set(value) - API_KEY_SCOPES)
        if forbidden:
            msg = "these permissions cannot be delegated to an API key: " + ", ".join(forbidden)
            raise ValueError(msg)
        return sorted(set(value), key=lambda p: p.value)


class ApiKeyResponse(ResponseModel):
    id: UUID
    name: str
    prefix: str
    scopes: list[str]
    service_account_id: UUID | None
    owner_user_id: UUID | None
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None


class CreatedApiKeyResponse(ApiKeyResponse):
    key: str
    warning: str = "This is the only time the full key is shown. Store it in a secret manager."


class AuditLogEntry(ResponseModel):
    id: int
    occurred_at: datetime
    action: str
    category: str
    outcome: str
    actor_type: str
    actor_id: UUID | None
    target_type: str | None
    target_id: str | None
    request_id: str | None
    ip_address: str | None
    details: dict[str, object]
