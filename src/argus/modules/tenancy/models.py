"""Tenancy tables.

Every table except ``organizations`` carries ``organization_id`` and is protected by RLS.
Children reference ``(organization_id, id)`` of their parents (composite same-tenant foreign keys),
so a row can never point into another tenant even if application code is wrong.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    ARRAY,
    BigInteger,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    LargeBinary,
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from argus.infrastructure.db.base import Base, CreatedAt, Timestamps, UUIDPrimaryKey, sql_in
from argus.security.permissions import OrgRole, ProjectRole

ORG_STATUSES = ("active", "suspended", "pending_deletion", "purging")
PLAN_NAMES = ("free", "team", "business", "enterprise")
ORG_ROLES = tuple(role.value for role in OrgRole)
PROJECT_ROLES = tuple(role.value for role in ProjectRole)
VISIBILITIES = ("organization", "restricted")


class Organization(Base, UUIDPrimaryKey, Timestamps):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(48), unique=True)
    status: Mapped[str] = mapped_column(String(24), default="active", server_default="active")
    plan: Mapped[str] = mapped_column(String(24), default="enterprise", server_default="enterprise")
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
    deletion_requested_at: Mapped[datetime | None]

    __table_args__ = (
        CheckConstraint(f"status IN {sql_in(ORG_STATUSES)}", name="status"),
        CheckConstraint(f"plan IN {sql_in(PLAN_NAMES)}", name="plan"),
        CheckConstraint("slug ~ '^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$'", name="slug_format"),
    )


class OrganizationMember(Base, CreatedAt):
    __tablename__ = "organization_members"

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(16))
    invited_by: Mapped[UUID | None]

    __table_args__ = (
        PrimaryKeyConstraint("organization_id", "user_id"),
        CheckConstraint(f"role IN {sql_in(ORG_ROLES)}", name="role"),
    )


class Invitation(Base, UUIDPrimaryKey, CreatedAt):
    __tablename__ = "invitations"

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    email: Mapped[str] = mapped_column(String(320))
    role: Mapped[str] = mapped_column(String(16))
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    invited_by: Mapped[UUID]
    expires_at: Mapped[datetime]
    accepted_at: Mapped[datetime | None]
    accepted_by: Mapped[UUID | None]
    revoked_at: Mapped[datetime | None]

    __table_args__ = (
        CheckConstraint(f"role IN {sql_in(ORG_ROLES)}", name="role"),
        CheckConstraint("email = lower(email)", name="email_lowercase"),
        Index(
            "uq_invitations_pending",
            "organization_id",
            "email",
            unique=True,
            postgresql_where=text("accepted_at IS NULL AND revoked_at IS NULL"),
        ),
    )


class Project(Base, UUIDPrimaryKey, Timestamps):
    __tablename__ = "projects"

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    visibility: Mapped[str] = mapped_column(
        String(16), default="organization", server_default="organization"
    )
    created_by: Mapped[UUID | None]
    archived_at: Mapped[datetime | None]
    corpus_version: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    """Bumped whenever the project's searchable knowledge changes (retrieval cache key)."""

    __table_args__ = (
        UniqueConstraint("organization_id", "name"),
        UniqueConstraint("organization_id", "id"),
        CheckConstraint(f"visibility IN {sql_in(VISIBILITIES)}", name="visibility"),
        Index("ix_projects_org_created", "organization_id", "created_at"),
    )


class ProjectMember(Base, CreatedAt):
    __tablename__ = "project_members"

    organization_id: Mapped[UUID]
    project_id: Mapped[UUID]
    user_id: Mapped[UUID]
    role: Mapped[str] = mapped_column(String(16))
    added_by: Mapped[UUID | None]

    __table_args__ = (
        PrimaryKeyConstraint("project_id", "user_id"),
        ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            ondelete="CASCADE",
        ),
        # A project member must be an organisation member; leaving the organisation cascades.
        ForeignKeyConstraint(
            ["organization_id", "user_id"],
            ["organization_members.organization_id", "organization_members.user_id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(f"role IN {sql_in(PROJECT_ROLES)}", name="role"),
        Index("ix_project_members_org_user", "organization_id", "user_id"),
    )


class ServiceAccount(Base, UUIDPrimaryKey, CreatedAt):
    __tablename__ = "service_accounts"

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    role: Mapped[str] = mapped_column(String(16))
    created_by: Mapped[UUID | None]
    disabled_at: Mapped[datetime | None]

    __table_args__ = (
        UniqueConstraint("organization_id", "name"),
        UniqueConstraint("organization_id", "id"),
        CheckConstraint(f"role IN {sql_in(ORG_ROLES)}", name="role"),
        CheckConstraint("role <> 'owner'", name="not_owner"),
    )


class ApiKey(Base, UUIDPrimaryKey, CreatedAt):
    __tablename__ = "api_keys"

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    key_id: Mapped[str] = mapped_column(String(16), unique=True)
    secret_hash: Mapped[bytes] = mapped_column(LargeBinary)
    name: Mapped[str] = mapped_column(String(100))
    owner_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    service_account_id: Mapped[UUID | None]
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String(48)))
    expires_at: Mapped[datetime | None]
    last_used_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
    created_by: Mapped[UUID | None]

    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "service_account_id"],
            ["service_accounts.organization_id", "service_accounts.id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "num_nonnulls(owner_user_id, service_account_id) = 1", name="exactly_one_owner"
        ),
        Index("ix_api_keys_org_created", "organization_id", "created_at"),
    )
