"""Baseline: extensions, RLS helper functions, runtime-role grants.

Revision ID: 0001
Revises:
Create Date: 2026-10-04
"""

from collections.abc import Sequence

from alembic import op

from argus.infrastructure.db import migration_support as ms

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # The role bootstrap (superuser) normally creates the extension; IF NOT EXISTS keeps this a
    # no-op that needs no extra privilege in that case.
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    # Tenant context readers. NULLIF(...)::uuid: an unset context is NULL and matches no row;
    # a malformed value raises - both fail closed.
    op.execute(
        """
        CREATE FUNCTION argus_current_org() RETURNS uuid
        LANGUAGE sql STABLE PARALLEL SAFE
        AS $$ SELECT NULLIF(current_setting('argus.org_id', true), '')::uuid $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION argus_current_user() RETURNS uuid
        LANGUAGE sql STABLE PARALLEL SAFE
        AS $$ SELECT NULLIF(current_setting('argus.user_id', true), '')::uuid $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION argus_reject_modification() RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'table % is append-only', TG_TABLE_NAME
                USING ERRCODE = 'insufficient_privilege';
        END
        $$
        """
    )

    role = ms.app_role()
    op.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    op.execute(f"GRANT USAGE ON SCHEMA public TO {role}")
    op.execute(f"GRANT SELECT ON TABLE alembic_version TO {role}")
    op.execute(f"GRANT EXECUTE ON FUNCTION argus_current_org(), argus_current_user() TO {role}")


def downgrade() -> None:
    role = ms.app_role()
    op.execute(f"REVOKE SELECT ON TABLE alembic_version FROM {role}")
    op.execute("DROP FUNCTION IF EXISTS argus_reject_modification()")
    op.execute("DROP FUNCTION IF EXISTS argus_current_user()")
    op.execute("DROP FUNCTION IF EXISTS argus_current_org()")
