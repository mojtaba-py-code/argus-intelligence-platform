"""Helpers used by Alembic revisions so every table gets identical security treatment.

Revisions call these instead of hand-writing policies, which keeps the RLS policy text, grants
and append-only triggers uniform and reviewable in one place.
"""

from __future__ import annotations

import re
from typing import Final

_IDENT: Final = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_app_role: str | None = None


def _check_identifier(value: str, what: str) -> str:
    if not _IDENT.fullmatch(value):
        msg = f"invalid {what}: {value!r}"
        raise ValueError(msg)
    return value


def configure(app_role: str) -> None:
    """Called by ``migrations/env.py`` with the runtime role from settings."""
    global _app_role
    _app_role = _check_identifier(app_role, "role name")


def app_role() -> str:
    if _app_role is None:  # pragma: no cover - env.py always configures it
        msg = "migration_support.configure() was not called"
        raise RuntimeError(msg)
    return _app_role


def grant_dml(table: str) -> str:
    table = _check_identifier(table, "table name")
    return f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {table} TO {app_role()}"


def grant_append_only(table: str) -> str:
    table = _check_identifier(table, "table name")
    return f"GRANT SELECT, INSERT ON TABLE {table} TO {app_role()}"


def tenant_rls(table: str, *, also_visible_to_user_column: str | None = None) -> list[str]:
    """Enable RLS with the standard tenant policy (fail closed when no context is set).

    ``also_visible_to_user_column`` additionally lets a user *read* rows where that column equals
    ``argus_current_user()`` (memberships must be listable before an organisation is selected).
    """
    table = _check_identifier(table, "table name")
    statements = [
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        (
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (organization_id = argus_current_org()) "
            "WITH CHECK (organization_id = argus_current_org())"
        ),
    ]
    if also_visible_to_user_column:
        column = _check_identifier(also_visible_to_user_column, "column name")
        statements.append(
            f"CREATE POLICY member_self_read ON {table} FOR SELECT "
            f"USING ({column} = argus_current_user())"
        )
    return statements


def drop_tenant_rls(table: str) -> list[str]:
    table = _check_identifier(table, "table name")
    return [
        f"DROP POLICY IF EXISTS member_self_read ON {table}",
        f"DROP POLICY IF EXISTS tenant_isolation ON {table}",
        f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY",
    ]


def append_only_trigger(table: str) -> list[str]:
    """Reject UPDATE/DELETE/TRUNCATE at the database level (defence beyond missing grants)."""
    table = _check_identifier(table, "table name")
    return [
        (
            f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION argus_reject_modification()"
        ),
        (
            f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION argus_reject_modification()"
        ),
    ]
