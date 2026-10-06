"""Identity (users, sessions, tokens, MFA) and the append-only audit log.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from argus.infrastructure.db import migration_support as ms

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_IDENTITY_TABLES = (
    "users",
    "user_sessions",
    "refresh_tokens",
    "one_time_tokens",
    "mfa_totp",
    "mfa_recovery_codes",
    "audit_chain_heads",
)


def upgrade() -> None:
    op.create_table(
        "audit_chain_heads",
        sa.Column("chain_key", sa.String(length=64), nullable=False),
        sa.Column("last_seq", sa.BigInteger(), nullable=False),
        sa.Column("last_hash", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint("chain_key", name=op.f("pk_audit_chain_heads")),
    )
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("chain_key", sa.String(length=64), nullable=False),
        sa.Column("chain_seq", sa.BigInteger(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("actor_type", sa.String(length=24), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("target_type", sa.String(length=48), nullable=True),
        sa.Column("target_id", sa.String(length=64), nullable=True),
        sa.Column("request_id", sa.String(length=128), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=256), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("prev_hash", sa.LargeBinary(), nullable=False),
        sa.Column("hash", sa.LargeBinary(), nullable=False),
        sa.CheckConstraint(
            "category IN ('authentication', 'account', 'authorization', 'organization', "
            "'data_access', 'configuration', 'research', 'agent', 'administration', 'security')",
            name=op.f("ck_audit_logs_category"),
        ),
        sa.CheckConstraint(
            "outcome IN ('success', 'failure', 'denied')", name=op.f("ck_audit_logs_outcome")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_logs")),
        sa.UniqueConstraint(
            "chain_key", "chain_seq", name=op.f("uq_audit_logs_chain_key_chain_seq")
        ),
    )
    op.create_index("ix_audit_logs_org_time", "audit_logs", ["organization_id", "occurred_at"])
    op.create_index("ix_audit_logs_user_time", "audit_logs", ["user_id", "occurred_at"])
    op.create_table(
        "users",
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("full_name", sa.String(length=200), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="active", nullable=False),
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column(
            "is_platform_admin", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column("failed_login_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("status IN ('active', 'disabled')", name=op.f("ck_users_status")),
        sa.CheckConstraint("email = lower(email)", name=op.f("ck_users_email_lowercase")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
    )
    op.create_table(
        "mfa_recovery_codes",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("code_hash", sa.LargeBinary(), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_mfa_recovery_codes_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mfa_recovery_codes")),
        sa.UniqueConstraint("code_hash", name=op.f("uq_mfa_recovery_codes_code_hash")),
    )
    op.create_index(op.f("ix_mfa_recovery_codes_user_id"), "mfa_recovery_codes", ["user_id"])
    op.create_table(
        "mfa_totp",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("secret_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_step", sa.BigInteger(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_mfa_totp_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("user_id", name=op.f("pk_mfa_totp")),
    )
    op.create_table(
        "one_time_tokens",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("token_hash", sa.LargeBinary(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "payload", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "purpose IN ('email_verification', 'password_reset', 'mfa_challenge')",
            name=op.f("ck_one_time_tokens_purpose"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_one_time_tokens_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_one_time_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_one_time_tokens_token_hash")),
    )
    op.create_index(op.f("ix_one_time_tokens_user_id"), "one_time_tokens", ["user_id"])
    op.create_table(
        "user_sessions",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(length=32), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=256), nullable=True),
        sa.Column("auth_method", sa.String(length=32), nullable=False),
        sa.Column("mfa_verified", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_sessions_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_sessions")),
    )
    op.create_index("ix_user_sessions_user_active", "user_sessions", ["user_id", "revoked_at"])
    op.create_table(
        "refresh_tokens",
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.LargeBinary(), nullable=False),
        sa.Column("parent_id", sa.Uuid(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["user_sessions.id"],
            name=op.f("fk_refresh_tokens_session_id_user_sessions"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_refresh_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_refresh_tokens_token_hash")),
    )
    op.create_index(op.f("ix_refresh_tokens_session_id"), "refresh_tokens", ["session_id"])

    # ---------------------------------------------------------------- privileges
    for table in _IDENTITY_TABLES:
        op.execute(ms.grant_dml(table))

    # audit_logs: insert + read only, tenant-filtered reads, append-only at the database level.
    role = ms.app_role()
    op.execute(ms.grant_append_only("audit_logs"))
    op.execute("ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY audit_read ON audit_logs FOR SELECT "
        "USING (organization_id = argus_current_org())"
    )
    op.execute(
        "CREATE POLICY audit_append ON audit_logs FOR INSERT "
        "WITH CHECK (organization_id IS NULL OR organization_id = argus_current_org())"
    )
    for statement in ms.append_only_trigger("audit_logs"):
        op.execute(statement)
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_logs FROM {role}")


def downgrade() -> None:
    op.drop_index(op.f("ix_refresh_tokens_session_id"), table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
    op.drop_index("ix_user_sessions_user_active", table_name="user_sessions")
    op.drop_table("user_sessions")
    op.drop_index(op.f("ix_one_time_tokens_user_id"), table_name="one_time_tokens")
    op.drop_table("one_time_tokens")
    op.drop_table("mfa_totp")
    op.drop_index(op.f("ix_mfa_recovery_codes_user_id"), table_name="mfa_recovery_codes")
    op.drop_table("mfa_recovery_codes")
    op.drop_table("users")
    op.drop_index("ix_audit_logs_user_time", table_name="audit_logs")
    op.drop_index("ix_audit_logs_org_time", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_table("audit_chain_heads")
