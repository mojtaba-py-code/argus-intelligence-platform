"""``argus`` - administrative command line.

Sub-commands are grouped by concern (``serve``, ``db``, ``keys``, ``config``...). Each command
returns a process exit code; errors print a one-line reason, never a traceback with settings.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from argus import __version__
from argus.core.config import ConfigurationError, Settings, load_settings

if TYPE_CHECKING:
    from argus.infrastructure.db import Database
    from argus.modules.audit.service import AuditService

Handler = Callable[[argparse.Namespace], int]


def _settings() -> Settings:
    return load_settings()


# ------------------------------------------------------------------------------------- serve
def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = _settings()  # validate before forking workers
    uvicorn.run(
        "argus.apps.api.main:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        workers=args.workers,
        proxy_headers=False,  # trusted-proxy handling lives in RequestContextMiddleware
        server_header=False,
        date_header=True,
        access_log=False,  # the request middleware writes structured access logs
        log_config=None,
        timeout_graceful_shutdown=int(settings.worker.shutdown_grace_s),
    )
    return 0


def _owner_dsn_required(settings: Settings) -> bool:
    """Operator commands run as the database owner. In production-like environments they refuse
    to fall back to the runtime DSN (which would fail later, half-way, with a privilege error)."""
    if settings.database.migration_url is None and settings.environment.is_production_like:
        print(
            "error: set ARGUS_DATABASE__MIGRATION_URL (owner role) for this command; "
            "runtime processes do not carry it",
            file=sys.stderr,
        )
        return True
    return False


# ---------------------------------------------------------------------------------------- db
def _cmd_db(args: argparse.Namespace) -> int:
    from alembic import command

    from argus.infrastructure.db.migrations import alembic_config

    settings = _settings()
    if args.db_command in {"migrate", "downgrade", "revision"} and _owner_dsn_required(settings):
        return 2
    config = alembic_config(settings)
    if args.db_command == "migrate":
        command.upgrade(config, args.revision)
    elif args.db_command == "downgrade":
        if settings.environment.is_production_like:
            print("refusing to downgrade in a production-like environment", file=sys.stderr)
            return 2
        command.downgrade(config, args.revision)
    elif args.db_command == "current":
        command.current(config, verbose=False)
    elif args.db_command == "check":
        command.check(config)
    elif args.db_command == "revision":
        command.revision(config, message=args.message, autogenerate=True)
    return 0


# -------------------------------------------------------------------------------------- keys
def _cmd_keys(args: argparse.Namespace) -> int:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from argus.core.crypto import generate_key_b64
    from argus.core.ids import random_lower_alnum

    kid = f"k{random_lower_alnum(8)}"
    pem = (
        Ed25519PrivateKey.generate()
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    enc_id = f"e{random_lower_alnum(8)}"
    values = {
        "ARGUS_AUTH__JWT_SIGNING_KEYS": json.dumps({kid: pem}),
        "ARGUS_AUTH__JWT_ACTIVE_KID": kid,
        "ARGUS_AUTH__API_KEY_PEPPER": generate_key_b64(),
        "ARGUS_SECURITY__AUDIT_HMAC_KEY": generate_key_b64(),
        "ARGUS_SECURITY__SIGNING_KEY": generate_key_b64(),
        "ARGUS_SECURITY__ENCRYPTION_KEYS": json.dumps({enc_id: generate_key_b64()}),
        "ARGUS_SECURITY__ACTIVE_ENCRYPTION_KEY": enc_id,
    }
    print("# Fresh key material - store it in your secret manager, never in Git.", file=sys.stderr)
    for name, value in values.items():
        print(f"{name}={json.dumps(value) if args.quote else value}")
    return 0


# ---------------------------------------------------------------------- worker / scheduler
def _cmd_worker(args: argparse.Namespace) -> int:  # noqa: ARG001 - uniform handler signature
    import asyncio

    from argus.apps.worker.main import run_worker

    asyncio.run(run_worker(_settings()))
    return 0


def _cmd_scheduler(args: argparse.Namespace) -> int:  # noqa: ARG001
    import asyncio

    from argus.apps.scheduler.main import run_scheduler

    asyncio.run(run_scheduler(_settings()))
    return 0


def _cmd_jobs(args: argparse.Namespace) -> int:
    import asyncio
    from uuid import UUID

    from argus.infrastructure.db import Database
    from argus.infrastructure.queue import JobQueue

    settings = _settings()

    async def run() -> int:
        database = Database(settings.database, application_name="argus-cli")
        queue = JobQueue(database)
        try:
            if args.jobs_command == "dead":
                for job in await queue.dead_letters(limit=args.limit):
                    print(json.dumps(job, default=str))
            elif args.jobs_command == "requeue":
                ok = await queue.requeue(UUID(args.job_id))
                print("requeued" if ok else "not found or not dead/failed")
                return 0 if ok else 1
            elif args.jobs_command == "depth":
                print(json.dumps(await queue.depth()))
        finally:
            await database.dispose()
        return 0

    return asyncio.run(run())


# ------------------------------------------------------------------------------------- users
def _cmd_users(args: argparse.Namespace) -> int:
    import asyncio
    import getpass

    from argus.apps.container import build_container

    settings = _settings()
    if args.users_command in {"disable", "enable"}:
        return _set_user_status(args, settings)
    password = (
        sys.stdin.readline().rstrip("\n")
        if args.password_stdin
        else getpass.getpass("Password (min 12 characters): ")
    )

    async def run() -> int:
        container = build_container(settings, role="cli")
        try:
            user_id = await container.auth.create_user(
                email=args.email.strip().lower(),
                password=password,
                full_name=args.name,
                verified=True,
                platform_admin=args.platform_admin,
            )
        finally:
            await container.aclose()
        print(f"created user {user_id}")
        return 0

    return asyncio.run(run())


def _set_user_status(args: argparse.Namespace, settings: Settings) -> int:
    """Incident containment: disable an account (sessions and API keys stop working at once)."""
    import asyncio

    from argus.apps.container import build_container
    from argus.modules.identity.administration import set_account_status

    async def run() -> int:
        container = build_container(settings, role="cli")
        try:
            change = await set_account_status(
                database=container.database,
                audit=container.audit,
                sessions=container.sessions,
                clock=container.clock,
                email=args.email,
                status="disabled" if args.users_command == "disable" else "active",
                reason=args.reason,
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        finally:
            await container.aclose()
        if change is None:
            print("no account with that e-mail address", file=sys.stderr)
            return 1
        if args.users_command == "disable":
            print(
                f"disabled {change.user_id}; {change.sessions_revoked} session(s) revoked; "
                "API keys owned by the account are refused while it is disabled"
            )
        else:
            print(f"enabled {change.user_id}; the user must sign in again")
        return 0

    return asyncio.run(run())


# ------------------------------------------------------------------------------------- audit
def _cmd_audit(args: argparse.Namespace) -> int:
    """Verify every audit chain, or export one for evidence. Runs with the owner DSN: RLS hides
    other tenants' rows from the runtime role, and both need all of them."""
    import asyncio

    from argus.core.clock import SystemClock
    from argus.infrastructure.db import Database
    from argus.modules.audit.service import AuditService
    from argus.security.keys import load_key_material

    settings = _settings()
    if _owner_dsn_required(settings):
        return 2
    owner_settings = settings.database.model_copy(
        update={"url": settings.database.migration_url or settings.database.url}
    )
    handle: TextIO | None = None
    if args.audit_command == "export":
        try:  # exclusive creation: an export never overwrites earlier evidence
            handle = Path(args.output).open("x", encoding="utf-8")  # noqa: SIM115
        except FileExistsError:
            print(f"error: {args.output} exists (exports never overwrite)", file=sys.stderr)
            return 2

    async def run() -> int:
        database = Database(owner_settings, application_name="argus-audit-verify")
        audit = AuditService(
            hmac_key=load_key_material(settings).audit_hmac_key,
            clock=SystemClock(),
            database=database,
        )
        failures = 0
        try:
            if handle is not None:
                return await _export_chain(database, audit, args.chain, handle)
            if args.audit_command == "prune":
                return await _prune_chain(
                    database, audit, args.chain, args.older_than_days, settings
                )
            async with database.session(read_only=True, snapshot=True) as session:
                for chain_key in await audit.chain_keys(session):
                    result = await audit.verify_chain(session, chain_key)
                    status = (
                        "ok"
                        if result.valid
                        else f"BROKEN at {result.first_broken_seq} ({result.reason})"
                    )
                    print(f"{chain_key}: {result.events} events - {status}")
                    failures += 0 if result.valid else 1
        finally:
            await database.dispose()
            if handle is not None:
                handle.close()
        return 1 if failures else 0

    return asyncio.run(run())


async def _export_chain(
    database: Database, audit: AuditService, chain_key: str, handle: TextIO
) -> int:
    """Write one chain as JSON lines (every hashed field, both hashes, hex-encoded), followed by
    a verification record - a self-contained copy that can be re-verified with the HMAC key.
    Read in one snapshot, so the export and its verification describe the same state."""
    from sqlalchemy import select

    from argus.modules.audit.models import AuditLog

    table = AuditLog.__table__
    written = 0
    async with database.session(read_only=True, snapshot=True) as session:
        result = await audit.verify_chain(session, chain_key)
        rows = await session.stream(
            select(table).where(table.c.chain_key == chain_key).order_by(table.c.chain_seq)
        )
        async for row in rows:
            record = {
                key: value.hex() if isinstance(value, bytes) else value
                for key, value in row._mapping.items()
            }
            handle.write(json.dumps(record, default=str, sort_keys=True) + "\n")
            written += 1
    verification = {
        "chain_key": chain_key,
        "events": result.events,
        "valid": result.valid,
        "first_broken_seq": result.first_broken_seq,
        "reason": result.reason,
    }
    # A pruned chain starts at a signed checkpoint: without it the copy cannot be re-verified.
    checkpoint = await _checkpoint_of(database, audit, chain_key)
    handle.write(json.dumps({"verification": verification, "checkpoint": checkpoint}) + "\n")
    status = "valid" if result.valid else f"BROKEN at {result.first_broken_seq} ({result.reason})"
    print(f"exported {written} events of {chain_key} to {handle.name} - chain {status}")
    return 0 if result.valid else 1


async def _checkpoint_of(
    database: Database, audit: AuditService, chain_key: str
) -> dict[str, object] | None:
    async with database.session(read_only=True) as session:
        return await audit.checkpoint(session, chain_key)


async def _prune_chain(
    database: Database, audit: AuditService, chain_key: str, days: int, settings: Settings
) -> int:
    """Prune with the retention the chain is owed, never less: the platform chain keeps
    ``platform.platform_audit_retention_days``, an organisation's chain its own
    ``retention.audit_days`` (and a purged organisation's chain the platform's)."""
    from datetime import UTC, datetime, timedelta
    from uuid import UUID

    from sqlalchemy import select

    from argus.modules.audit.models import AuditChainHead
    from argus.modules.tenancy.models import Organization
    from argus.modules.tenancy.schemas import OrganizationSettings

    organization_id: UUID | None = None
    if chain_key != "platform":
        try:
            organization_id = UUID(chain_key)
        except ValueError:
            print("error: --chain is an organisation id or 'platform'", file=sys.stderr)
            return 2
        chain_key = str(organization_id)  # the stored form: lower case, hyphenated
    async with database.session(read_only=True) as session:
        exists = (
            await session.execute(
                select(AuditChainHead.chain_key).where(AuditChainHead.chain_key == chain_key)
            )
        ).first()
        org_settings = (
            (
                await session.execute(
                    select(Organization.settings).where(Organization.id == organization_id)
                )
            ).first()
            if organization_id is not None
            else None
        )
    if exists is None:
        print(f"error: there is no audit chain {chain_key}", file=sys.stderr)
        return 2
    minimum = settings.platform.platform_audit_retention_days
    if org_settings is not None:
        minimum = OrganizationSettings.model_validate(org_settings[0] or {}).retention.audit_days
    if days < minimum:
        print(
            f"error: the chain {chain_key} keeps {minimum} days of audit events;"
            f" --older-than-days must be at least {minimum}",
            file=sys.stderr,
        )
        return 2
    result = await audit.prune(
        chain_key,
        older_than=datetime.now(UTC) - timedelta(days=days),
        organization_id=organization_id,
        database=database,
    )
    if result.refused:
        print(f"refused: {result.refused}", file=sys.stderr)
        return 1
    print(f"pruned {result.pruned} events of {chain_key} (checkpoint at {result.through_seq})")
    return 0


# ------------------------------------------------------------------------------------- orgs
def _cmd_orgs(args: argparse.Namespace) -> int:
    """Platform administration on the owner role: row-level security hides other tenants from
    the runtime role, and these commands act across organisations by design."""
    import asyncio
    from uuid import UUID

    from argus.core.clock import SystemClock
    from argus.infrastructure.db import Database
    from argus.infrastructure.storage import create_object_store
    from argus.modules.audit.service import AuditService
    from argus.modules.platform.lifecycle import LifecycleError, OrganizationLifecycle
    from argus.security.keys import load_key_material

    settings = _settings()
    if _owner_dsn_required(settings):
        return 2
    owner_settings = settings.database.model_copy(
        update={"url": settings.database.migration_url or settings.database.url}
    )

    async def run() -> int:
        database = Database(owner_settings, application_name="argus-orgs")
        clock = SystemClock()
        audit = AuditService(
            hmac_key=load_key_material(settings).audit_hmac_key, clock=clock, database=database
        )
        storage = create_object_store(settings.storage)
        lifecycle = OrganizationLifecycle(database, audit, storage, clock, settings.platform)
        try:
            if args.orgs_command == "list":
                for row in await lifecycle.list():
                    print(
                        json.dumps(
                            {
                                "id": str(row.id),
                                "slug": row.slug,
                                "status": row.status,
                                "plan": row.plan,
                                "members": row.members,
                                "created_at": row.created_at.isoformat(),
                                "deletion_requested_at": row.deletion_requested_at.isoformat()
                                if row.deletion_requested_at
                                else None,
                            }
                        )
                    )
                return 0
            org = UUID(args.org)
            if args.orgs_command == "suspend":
                await lifecycle.suspend(org, reason=args.reason)
            elif args.orgs_command == "resume":
                await lifecycle.resume(org, reason=args.reason)
            elif args.orgs_command == "restore":
                await lifecycle.restore(org, reason=args.reason)
            elif args.orgs_command == "set-plan":
                await lifecycle.set_plan(org, args.plan, reason=args.reason)
            elif args.orgs_command == "purge":
                blobs = await lifecycle.purge(org, force=args.before_grace_period)
                print(f"purged {org} ({blobs} stored objects deleted)")
                return 0
        except (LifecycleError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        else:
            print(f"{args.orgs_command}: done for {org}")
            return 0
        finally:
            await storage.aclose()
            await database.dispose()

    return asyncio.run(run())


# ----------------------------------------------------------------------------------- prompts
def _cmd_prompts(args: argparse.Namespace) -> int:
    import asyncio

    from argus.apps.container import build_container

    settings = _settings()

    async def run() -> int:
        container = build_container(settings, role="cli")
        try:
            prompts = container.prompts
            if args.prompts_command == "list":
                pinned = await prompts.deployments()
                for name in prompts.registry.names():
                    print(
                        json.dumps(
                            {
                                "name": name,
                                "versions": prompts.registry.versions(name),
                                "active": await prompts.active_version(name),
                                "pinned": name in pinned,
                            }
                        )
                    )
            elif args.prompts_command == "deploy":
                await prompts.deploy(args.name, args.version, deployed_by=args.by)
                print(f"{args.name} v{args.version} is now active in {settings.environment.value}")
        finally:
            await container.aclose()
        return 0

    return asyncio.run(run())


# -------------------------------------------------------------------------------------- eval
def _cmd_eval(args: argparse.Namespace) -> int:
    """Run an evaluation dataset through the real application and gate on the baseline.

    Use a disposable database: the run creates organisations and processes the job queue."""
    import asyncio
    import tempfile

    from argus.apps.evaluation.runner import run_evaluation
    from argus.modules.evaluation.baseline import compare, load_baseline, write_baseline
    from argus.modules.evaluation.dataset import load_dataset

    settings = _settings()
    dataset = load_dataset(Path(args.dataset))
    tags = {tag.strip() for tag in args.tags.split(",") if tag.strip()} if args.tags else None
    storage = Path(args.storage) if args.storage else Path(tempfile.mkdtemp(prefix="argus-eval-"))
    summary = asyncio.run(
        run_evaluation(
            settings, dataset, storage_root=storage, tags=tags, repeat=args.repeat, live=args.live
        )
    )
    baseline_path = Path(args.baseline)
    baseline = load_baseline(baseline_path, dataset.name)
    if baseline is not None and not args.write_baseline:
        summary.regressions = [str(r) for r in compare(summary.metrics, baseline)]
    for result in summary.results:
        state = "ok" if not result.failures else "FAIL"
        print(f"{result.case_id:<28} {result.status:<10} {state}")
        for failure in result.failures:
            print(f"    - {failure}")
    print("metrics:", json.dumps(summary.metrics, sort_keys=True))
    for regression in summary.regressions:
        print(f"REGRESSION {regression}")
    if args.output:
        Path(args.output).write_text(json.dumps(summary.to_json(), indent=2), encoding="utf-8")
    if args.write_baseline:
        if summary.failures:
            print("refusing to write a baseline from a run with failing cases", file=sys.stderr)
            return 1
        write_baseline(baseline_path, dataset.name, dataset.version, summary.metrics)
        print(f"baseline written to {baseline_path}")
    return 1 if summary.failures or summary.regressions else 0


# -------------------------------------------------------------------------------- killswitch
def _cmd_killswitch(args: argparse.Namespace) -> int:
    """Engage, release and list kill switches. Uses the owner DSN: platform-wide switches are
    writable only by the owner role, and listing must see every organisation's switches."""
    import asyncio
    from datetime import timedelta
    from uuid import UUID

    from argus.core.clock import SystemClock
    from argus.infrastructure.db import Database
    from argus.modules.agents.killswitch import InvalidSwitch, KillSwitchService
    from argus.modules.audit.service import AuditService
    from argus.security.keys import load_key_material

    settings = _settings()
    if _owner_dsn_required(settings):
        return 2
    owner_settings = settings.database.model_copy(
        update={"url": settings.database.migration_url or settings.database.url}
    )

    async def run() -> int:
        database = Database(owner_settings, application_name="argus-killswitch")
        clock = SystemClock()
        audit = AuditService(
            hmac_key=load_key_material(settings).audit_hmac_key, clock=clock, database=database
        )
        switches = KillSwitchService(database, clock, audit=audit)
        try:
            if args.killswitch_command == "list":
                for view in await switches.list_switches(include_inactive=args.all):
                    print(
                        json.dumps(
                            {
                                "id": str(view.id),
                                "scope": str(view.organization_id or "platform"),
                                "kind": view.kind,
                                "target": view.target,
                                "active": view.active,
                                "reason": view.reason,
                                "by": view.created_by,
                                "created_at": view.created_at.isoformat(),
                                "expires_at": view.expires_at.isoformat()
                                if view.expires_at
                                else None,
                            }
                        )
                    )
            elif args.killswitch_command == "engage":
                expires = (
                    clock.now() + timedelta(minutes=args.expires_in)
                    if args.expires_in is not None
                    else None
                )
                switch_id = await switches.engage(
                    kind=args.kind,
                    target=args.target,
                    reason=args.reason,
                    created_by=args.by,
                    organization_id=UUID(args.org) if args.org else None,
                    expires_at=expires,
                )
                print(f"engaged {switch_id} (takes effect everywhere within a few seconds)")
            elif args.killswitch_command == "release":
                if not await switches.release(UUID(args.switch_id), released_by=args.by):
                    print("no active switch with that id", file=sys.stderr)
                    return 1
                print(f"released {args.switch_id}")
        except (InvalidSwitch, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        finally:
            await database.dispose()
        return 0

    return asyncio.run(run())


# ------------------------------------------------------------------------------------ config
def _cmd_config(args: argparse.Namespace) -> int:
    settings = _settings()
    if args.config_command == "check":
        print(f"configuration valid for environment '{settings.environment.value}'")
    elif args.config_command == "show":
        print(json.dumps(settings.redacted_summary(), indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="argus", description="Argus administration")
    parser.add_argument("--version", action="version", version=f"argus {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the HTTP API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--workers", type=int, default=1)
    serve.set_defaults(handler=_cmd_serve)

    db = sub.add_parser("db", help="database migrations (runs as the owner role)")
    db_sub = db.add_subparsers(dest="db_command", required=True)
    migrate = db_sub.add_parser("migrate", help="upgrade to a revision (default: head)")
    migrate.add_argument("revision", nargs="?", default="head")
    down = db_sub.add_parser("downgrade", help="downgrade (development only)")
    down.add_argument("revision")
    db_sub.add_parser("current", help="show the current revision")
    db_sub.add_parser("check", help="fail if models and migrations have drifted")
    rev = db_sub.add_parser("revision", help="autogenerate a new revision (review it!)")
    rev.add_argument("-m", "--message", required=True)
    db.set_defaults(handler=_cmd_db)

    keys = sub.add_parser("keys", help="key material")
    keys_sub = keys.add_subparsers(dest="keys_command", required=True)
    gen = keys_sub.add_parser("generate", help="print a fresh set of secrets as env lines")
    gen.add_argument("--quote", action="store_true", help="JSON-quote values (for .env files)")
    keys.set_defaults(handler=_cmd_keys)

    sub.add_parser("worker", help="run a queue worker").set_defaults(handler=_cmd_worker)
    sub.add_parser("scheduler", help="run the periodic scheduler").set_defaults(
        handler=_cmd_scheduler
    )
    jobs = sub.add_parser("jobs", help="inspect the job queue")
    jobs_sub = jobs.add_subparsers(dest="jobs_command", required=True)
    dead = jobs_sub.add_parser("dead", help="list dead-lettered and failed jobs")
    dead.add_argument("--limit", type=int, default=50)
    requeue = jobs_sub.add_parser("requeue", help="re-queue a dead or failed job")
    requeue.add_argument("job_id")
    jobs_sub.add_parser("depth", help="queued jobs per queue")
    jobs.set_defaults(handler=_cmd_jobs)

    users = sub.add_parser("users", help="user administration")
    users_sub = users.add_subparsers(dest="users_command", required=True)
    create = users_sub.add_parser("create", help="create a verified user (password prompted)")
    create.add_argument("--email", required=True)
    create.add_argument("--name", required=True)
    create.add_argument("--platform-admin", action="store_true")
    create.add_argument(
        "--password-stdin", action="store_true", help="read the password from standard input"
    )
    for name, text in (
        ("disable", "block an account now: sign-in, open sessions and its API keys (audited)"),
        ("enable", "allow an account again (sessions stay revoked; audited)"),
    ):
        command = users_sub.add_parser(name, help=text)
        command.add_argument("--email", required=True)
        command.add_argument("--reason", required=True, help="kept in the audit log")
    users.set_defaults(handler=_cmd_users)

    audit = sub.add_parser("audit", help="audit log")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    audit_sub.add_parser("verify", help="verify every HMAC chain (exit 1 if any is broken)")
    prune = audit_sub.add_parser(
        "prune", help="remove old events of a chain behind a signed checkpoint (retention)"
    )
    prune.add_argument("--chain", required=True, help="an organisation id, or 'platform'")
    prune.add_argument("--older-than-days", type=int, required=True)
    export = audit_sub.add_parser(
        "export", help="write one chain as JSON lines with its verification (evidence copy)"
    )
    export.add_argument("--chain", required=True, help="an organisation id, or 'platform'")
    export.add_argument("--output", required=True, help="a new file (never overwritten)")
    audit.set_defaults(handler=_cmd_audit)

    prompts = sub.add_parser("prompts", help="prompt registry and deployments")
    prompts_sub = prompts.add_subparsers(dest="prompts_command", required=True)
    prompts_sub.add_parser("list", help="prompts, their versions and the active version")
    deploy = prompts_sub.add_parser("deploy", help="activate a version (older = rollback; audited)")
    deploy.add_argument("name")
    deploy.add_argument("version", type=int)
    deploy.add_argument("--by", required=True, help="who is deploying (recorded in the audit log)")
    prompts.set_defaults(handler=_cmd_prompts)

    evaluate = sub.add_parser("eval", help="AI evaluation datasets and the regression gate")
    eval_sub = evaluate.add_subparsers(dest="eval_command", required=True)
    run = eval_sub.add_parser("run", help="run a dataset (offline unless --live)")
    run.add_argument("--dataset", default="evals/datasets/default.yaml")
    run.add_argument("--baseline", default="evals/baseline.json")
    run.add_argument("--tags", help="comma-separated case tags to run (default: all)")
    run.add_argument(
        "--repeat", type=int, default=1, help="runs per case (2+ measures consistency)"
    )
    run.add_argument("--live", action="store_true", help="use the configured model providers")
    run.add_argument("--output", help="write the full JSON result here")
    run.add_argument("--storage", help="directory for uploaded evaluation documents")
    run.add_argument("--write-baseline", action="store_true", help="accept this run as baseline")
    evaluate.set_defaults(handler=_cmd_eval)

    kill = sub.add_parser("killswitch", help="stop agents, tools, providers or models (audited)")
    kill_sub = kill.add_subparsers(dest="killswitch_command", required=True)
    kill_list = kill_sub.add_parser("list", help="active switches (all with --all)")
    kill_list.add_argument("--all", action="store_true", help="include released switches")
    engage = kill_sub.add_parser("engage", help="engage a switch")
    engage.add_argument("kind", choices=["all", "agent", "tool", "provider", "model"])
    engage.add_argument("target", help="a name (analyst, search_documents, anthropic...) or *")
    engage.add_argument("--reason", required=True)
    engage.add_argument("--by", required=True, help="who is engaging it (audited)")
    engage.add_argument("--org", help="organisation id; omit for a platform-wide switch")
    engage.add_argument("--expires-in", type=int, metavar="MINUTES", help="auto-release")
    release = kill_sub.add_parser("release", help="release a switch")
    release.add_argument("switch_id")
    release.add_argument("--by", required=True, help="who is releasing it (audited)")
    kill.set_defaults(handler=_cmd_killswitch)

    config = sub.add_parser("config", help="configuration")
    config_sub = config.add_subparsers(dest="config_command", required=True)
    config_sub.add_parser("check", help="validate configuration for this environment")
    config_sub.add_parser("show", help="print configuration with secrets redacted")
    config.set_defaults(handler=_cmd_config)

    orgs = sub.add_parser("orgs", help="organisation lifecycle and plans (owner role, audited)")
    orgs_sub = orgs.add_subparsers(dest="orgs_command", required=True)
    orgs_sub.add_parser("list", help="every organisation with status, plan and members")
    for name, text in (
        ("suspend", "suspend: members get 403, API keys and monitors stop"),
        ("resume", "end a suspension"),
        ("restore", "cancel a deletion within the grace period"),
    ):
        command = orgs_sub.add_parser(name, help=text)
        command.add_argument("--org", required=True)
        command.add_argument("--reason", required=True)
    set_plan = orgs_sub.add_parser("set-plan", help="change an organisation's plan")
    set_plan.add_argument("--org", required=True)
    set_plan.add_argument(
        "--plan", required=True, choices=["free", "team", "business", "enterprise"]
    )
    set_plan.add_argument("--reason", required=True)
    purge = orgs_sub.add_parser("purge", help="delete an organisation pending deletion, now")
    purge.add_argument("--org", required=True)
    purge.add_argument(
        "--before-grace-period", action="store_true", help="purge even inside the grace period"
    )
    orgs.set_defaults(handler=_cmd_orgs)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Handler = args.handler
    try:
        return handler(args)
    except ConfigurationError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
