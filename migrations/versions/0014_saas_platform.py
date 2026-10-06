"""SaaS platform: plans, retention with audit checkpoints, organisation exports and purge.

* ``organizations.plan``: CHECK over the plan catalogue; new organisations default to
  ``enterprise`` (self-hosted: no quotas). Existing organisations move from the never-enforced
  ``free`` default to ``enterprise`` - enforcing quotas must not change behaviour for them.
* ``organizations.status`` gains ``purging``: a purge marks the organisation first, so it can no
  longer be restored once its files start disappearing, and an interrupted purge is resumed.
* ``audit_checkpoints`` (append-only, written only by ``argus_prune_audit``; the runtime role reads
  its own organisation's rows) and a new ``argus_reject_modification()`` whose single exception
  is a DELETE on ``audit_logs`` by the schema owner inside ``argus_prune_audit`` - the runtime role
  has no DELETE grant and cannot reach it. ``argus_audit_insert_guard`` refuses audit rows at or
  below a chain's checkpoint (sequence numbers freed by pruning cannot be reused for forgeries).
* ``argus_prune_audit(chain, seq, hash, mac)``: SECURITY DEFINER; an organisation context prunes
  only its own chain, the platform chain only the owner role itself; the checkpoint must match
  the stored chain; nothing younger than 90 days is ever pruned (one day of clock tolerance).
* ``organization_exports`` (tenant table; at most one pending export per organisation).
* ``argus_organizations_for_retention(after, max_rows)`` returns ids and *only* the retention
  settings of active and suspended organisations; ``argus_organizations_due_for_purge(before,
  max_rows)`` returns ids, unfinished purges first.
* ``argus_claim_due_monitors`` skips monitors of organisations that are not active.
* Notification event ``platform.export.ready``.

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from argus.infrastructure.db import migration_support as ms

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_FUNCTIONS = (
    "argus_prune_audit(text, bigint, bytea, bytea)",
    "argus_organizations_for_retention(uuid, integer)",
    "argus_organizations_due_for_purge(timestamptz, integer)",
)
_EVENTS_0013 = (
    "research.job.completed",
    "research.job.failed",
    "approval.requested",
    "monitor.change.detected",
    "monitor.paused",
    "security.audit.integrity_failed",
    "security.kill_switch.engaged",
)
_EVENTS_0014 = (*_EVENTS_0013, "platform.export.ready")

_REJECT_STRICT = """
CREATE OR REPLACE FUNCTION argus_reject_modification() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'table % is append-only', TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END
$$
"""
_REJECT_WITH_PRUNE = """
CREATE OR REPLACE FUNCTION argus_reject_modification() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- The single exception: argus_prune_audit() removing audit rows behind a signed checkpoint.
    -- It runs as the schema owner and marks its own transaction; the runtime role has no DELETE
    -- grant on audit_logs, so it never reaches this trigger with a DELETE at all.
    IF TG_OP = 'DELETE' AND TG_TABLE_NAME = 'audit_logs'
       AND current_setting('argus.audit_prune', true) = 'on'
       AND current_user = (SELECT tableowner FROM pg_catalog.pg_tables
                            WHERE schemaname = 'public' AND tablename = 'audit_logs')
    THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'table % is append-only', TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END
$$
"""
_CLAIM_ANY_ORG = """
CREATE OR REPLACE FUNCTION argus_claim_due_monitors(max_rows integer)
RETURNS TABLE (organization_id uuid, monitor_id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    UPDATE public.monitors m
       SET next_run_at = now() + make_interval(mins => m.interval_minutes),
           updated_at = now()
      FROM (SELECT id FROM public.monitors
             WHERE status = 'active' AND next_run_at <= now()
             ORDER BY next_run_at
             LIMIT least(greatest(max_rows, 0), 1000)
             FOR UPDATE SKIP LOCKED) due
     WHERE m.id = due.id
 RETURNING m.organization_id, m.id
$$
"""
_CLAIM_ACTIVE_ORGS = """
CREATE OR REPLACE FUNCTION argus_claim_due_monitors(max_rows integer)
RETURNS TABLE (organization_id uuid, monitor_id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    UPDATE public.monitors m
       SET next_run_at = now() + make_interval(mins => m.interval_minutes),
           updated_at = now()
      FROM (SELECT mon.id FROM public.monitors mon
              JOIN public.organizations o ON o.id = mon.organization_id
             WHERE mon.status = 'active' AND mon.next_run_at <= now() AND o.status = 'active'
             ORDER BY mon.next_run_at
             LIMIT least(greatest(max_rows, 0), 1000)
             FOR UPDATE OF mon SKIP LOCKED) due
     WHERE m.id = due.id
 RETURNING m.organization_id, m.id
$$
"""


_STATUSES_0003 = "status IN ('active', 'suspended', 'pending_deletion')"
_STATUSES_0014 = "status IN ('active', 'suspended', 'pending_deletion', 'purging')"
_INSERT_GUARD = """
CREATE FUNCTION argus_audit_insert_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    -- Pruning frees the sequence numbers below a checkpoint; verification starts above it, so a
    -- row added down there would never be checked. None may be added.
    IF EXISTS (SELECT 1 FROM public.audit_checkpoints
                WHERE chain_key = NEW.chain_key AND seq >= NEW.chain_seq) THEN
        RAISE EXCEPTION 'audit events at or below a checkpoint cannot be added'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$
"""


def _event_check(events: tuple[str, ...]) -> str:
    return "event IN (" + ", ".join(f"'{event}'" for event in events) + ")"


def upgrade() -> None:
    # ---------------------------------------------------------------------------- plans
    op.execute("UPDATE organizations SET plan = 'enterprise' WHERE plan = 'free'")
    op.alter_column("organizations", "plan", server_default="enterprise")
    op.create_check_constraint(
        op.f("ck_organizations_plan"),
        "organizations",
        "plan IN ('free', 'team', 'business', 'enterprise')",
    )
    op.drop_constraint(op.f("ck_organizations_status"), "organizations", type_="check")
    op.create_check_constraint(op.f("ck_organizations_status"), "organizations", _STATUSES_0014)

    # --------------------------------------------------------------- audit checkpoints
    op.create_table(
        "audit_checkpoints",
        sa.Column("chain_key", sa.String(length=64), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("hash", sa.LargeBinary(), nullable=False),
        sa.Column("mac", sa.LargeBinary(), nullable=False),
        sa.Column("pruned_rows", sa.BigInteger(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("chain_key", "seq", name=op.f("pk_audit_checkpoints")),
    )
    op.execute(f"GRANT SELECT ON TABLE audit_checkpoints TO {ms.app_role()}")
    for statement in ms.append_only_trigger("audit_checkpoints"):
        op.execute(statement)
    # The runtime role reads its own organisation's checkpoints (to verify its chain); the
    # platform chain's are read by the owner role, which row-level security does not restrict.
    op.execute("ALTER TABLE audit_checkpoints ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY own_chain ON audit_checkpoints FOR SELECT "
        "USING (chain_key = CAST(argus_current_org() AS text))"
    )
    op.execute(_REJECT_WITH_PRUNE)
    op.execute(_INSERT_GUARD)
    op.execute("REVOKE ALL ON FUNCTION argus_audit_insert_guard() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER audit_logs_above_checkpoint BEFORE INSERT ON audit_logs "
        "FOR EACH ROW EXECUTE FUNCTION argus_audit_insert_guard()"
    )
    op.execute(
        """
        CREATE FUNCTION argus_prune_audit(
            p_chain_key text, p_through_seq bigint, p_hash bytea, p_mac bytea
        ) RETURNS bigint
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
            v_hash bytea;
            v_at timestamptz;
            v_checkpoint bigint;
            v_deleted bigint;
        BEGIN
            IF p_chain_key = 'platform' THEN
                IF session_user <> current_user THEN
                    RAISE EXCEPTION 'the platform chain is pruned by the schema owner only'
                        USING ERRCODE = 'insufficient_privilege';
                END IF;
            ELSIF p_chain_key IS DISTINCT FROM current_setting('argus.org_id', true) THEN
                RAISE EXCEPTION 'an organisation can prune only its own audit chain'
                    USING ERRCODE = 'insufficient_privilege';
            END IF;
            SELECT hash, occurred_at INTO v_hash, v_at FROM public.audit_logs
             WHERE chain_key = p_chain_key AND chain_seq = p_through_seq;
            IF v_hash IS NULL OR v_hash <> p_hash THEN
                RAISE EXCEPTION 'the checkpoint does not match the stored chain'
                    USING ERRCODE = 'data_exception';
            END IF;
            IF v_at > now() - interval '89 days' THEN
                RAISE EXCEPTION 'audit events younger than 90 days are never pruned'
                    USING ERRCODE = 'insufficient_privilege';
            END IF;
            SELECT max(seq) INTO v_checkpoint FROM public.audit_checkpoints
             WHERE chain_key = p_chain_key;
            IF v_checkpoint IS NOT NULL AND p_through_seq <= v_checkpoint THEN
                RETURN 0;
            END IF;
            PERFORM set_config('argus.audit_prune', 'on', true);
            DELETE FROM public.audit_logs
             WHERE chain_key = p_chain_key AND chain_seq <= p_through_seq;
            GET DIAGNOSTICS v_deleted = ROW_COUNT;
            PERFORM set_config('argus.audit_prune', 'off', true);
            INSERT INTO public.audit_checkpoints (chain_key, seq, hash, mac, pruned_rows)
            VALUES (p_chain_key, p_through_seq, p_hash, p_mac, v_deleted);
            RETURN v_deleted;
        END
        $$
        """
    )

    # ---------------------------------------------------------------------- exports
    op.create_table(
        "organization_exports",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("requested_by", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="pending", nullable=False),
        sa.Column("storage_key", sa.String(length=255), nullable=True),
        sa.Column("byte_size", sa.BigInteger(), nullable=True),
        sa.Column("sha256", sa.LargeBinary(), nullable=True),
        sa.Column("documents_included", sa.Boolean(), nullable=True),
        sa.Column("error_code", sa.String(length=48), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'ready', 'failed', 'expired')",
            name=op.f("ck_organization_exports_status"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_organization_exports_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_organization_exports")),
    )
    op.create_index(
        "ix_organization_exports_org_created",
        "organization_exports",
        ["organization_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "uq_organization_exports_one_pending",
        "organization_exports",
        ["organization_id"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.execute(ms.grant_dml("organization_exports"))
    for statement in ms.tenant_rls("organization_exports"):
        op.execute(statement)

    # ------------------------------------------------------- lifecycle and retention
    op.execute(
        """
        CREATE FUNCTION argus_organizations_for_retention(p_after uuid, p_max_rows integer)
        RETURNS TABLE (organization_id uuid, settings jsonb)
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT o.id, jsonb_build_object('retention', coalesce(o.settings -> 'retention', '{}'))
              FROM public.organizations o
             WHERE o.status IN ('active', 'suspended') AND (p_after IS NULL OR o.id > p_after)
             ORDER BY o.id
             LIMIT least(greatest(p_max_rows, 0), 1000)
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION argus_organizations_due_for_purge(p_before timestamptz, p_max_rows integer)
        RETURNS TABLE (organization_id uuid)
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT o.id FROM public.organizations o
             WHERE o.status = 'purging'
                OR (o.status = 'pending_deletion' AND o.deletion_requested_at <= p_before)
             ORDER BY o.status = 'purging' DESC, o.deletion_requested_at
             LIMIT least(greatest(p_max_rows, 0), 100)
        $$
        """
    )
    op.execute(_CLAIM_ACTIVE_ORGS)
    role = ms.app_role()
    for function in _FUNCTIONS:
        op.execute(f"REVOKE ALL ON FUNCTION {function} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION {function} TO {role}")

    # ------------------------------------------------------------------ notifications
    op.drop_constraint(op.f("ck_notifications_event"), "notifications", type_="check")
    op.create_check_constraint(
        op.f("ck_notifications_event"), "notifications", _event_check(_EVENTS_0014)
    )


def downgrade() -> None:
    pruned = op.get_bind().execute(sa.text("SELECT EXISTS (SELECT 1 FROM audit_checkpoints)"))
    if pruned.scalar():
        msg = (
            "audit chains were pruned behind checkpoints; without 0014 they could no longer be "
            "verified - restore a backup taken before the first prune instead of downgrading"
        )
        raise RuntimeError(msg)
    op.execute("DELETE FROM notifications WHERE event = 'platform.export.ready'")
    op.drop_constraint(op.f("ck_notifications_event"), "notifications", type_="check")
    op.create_check_constraint(
        op.f("ck_notifications_event"), "notifications", _event_check(_EVENTS_0013)
    )
    op.execute(_CLAIM_ANY_ORG)
    for function in _FUNCTIONS:
        op.execute(f"DROP FUNCTION IF EXISTS {function}")
    for statement in ms.drop_tenant_rls("organization_exports"):
        op.execute(statement)
    op.execute("DROP INDEX IF EXISTS uq_organization_exports_one_pending")
    op.drop_index("ix_organization_exports_org_created", table_name="organization_exports")
    op.drop_table("organization_exports")
    op.execute("DROP TRIGGER IF EXISTS audit_logs_above_checkpoint ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS argus_audit_insert_guard()")
    op.execute(_REJECT_STRICT)
    op.drop_table("audit_checkpoints")
    op.execute("UPDATE organizations SET status = 'pending_deletion' WHERE status = 'purging'")
    op.drop_constraint(op.f("ck_organizations_status"), "organizations", type_="check")
    op.create_check_constraint(op.f("ck_organizations_status"), "organizations", _STATUSES_0003)
    op.drop_constraint(op.f("ck_organizations_plan"), "organizations", type_="check")
    op.alter_column("organizations", "plan", server_default="free")
