"""Run a local PostgreSQL 16 + pgvector without Docker (development and tests).

Uses the ``pgserver`` package (``uv sync --group localdb``, or ``pip install pgserver`` in any
short-path virtual environment - on Windows a long venv path can break its DLL loading).

    python scripts/local_postgres.py start --data <dir>     # start (idempotent) + bootstrap roles
    python scripts/local_postgres.py stop  --data <dir>

``start`` prints the DSNs to put in ``.env``:

* ``ARGUS_DATABASE__URL``            - runtime role ``argus_app`` (no DDL, no BYPASSRLS)
* ``ARGUS_DATABASE__MIGRATION_URL``  - owner role ``argus_owner`` (migrations only)
* ``ARGUS_TEST_DATABASE_URL``        - superuser, used by the test-suite to create throwaway DBs

The roles get fixed *development* passwords. This script is never used in production, where roles
come from infrastructure-as-code (see docker/postgres/init for the container equivalent).
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

DEV_PASSWORDS = {"argus_owner": "argus_owner_dev_password", "argus_app": "argus_app_dev_password"}


def _psql(server: Any, sql: str, database: str | None = None) -> str:
    from pgserver import postgres_server  # type: ignore[import-not-found]

    exe = Path(postgres_server.POSTGRES_BIN_PATH) / (
        "psql.exe" if sys.platform == "win32" else "psql"
    )
    result = subprocess.run(
        [str(exe), "-v", "ON_ERROR_STOP=1", "-q", server.get_uri(database)],
        input=sql.encode(),
        capture_output=True,
        check=True,
    )
    return result.stdout.decode()


def _bootstrap_sql(database: str) -> str:
    owner, app = "argus_owner", "argus_app"
    return f"""
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{owner}') THEN
    CREATE ROLE {owner} LOGIN PASSWORD '{DEV_PASSWORDS[owner]}';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{app}') THEN
    CREATE ROLE {app} LOGIN PASSWORD '{DEV_PASSWORDS[app]}'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  END IF;
END $$;
SELECT 'CREATE DATABASE {database} OWNER {owner}'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = '{database}')\\gexec
"""


def start(data_dir: Path, database: str) -> int:
    import pgserver

    data_dir.mkdir(parents=True, exist_ok=True)
    server = pgserver.get_server(str(data_dir), cleanup_mode=None)
    _psql(server, _bootstrap_sql(database))
    _psql(server, "CREATE EXTENSION IF NOT EXISTS vector;", database)
    parts = urlsplit(server.get_uri())
    host, port = parts.hostname or "127.0.0.1", parts.port or 5432
    app, owner = DEV_PASSWORDS["argus_app"], DEV_PASSWORDS["argus_owner"]
    print(f"ARGUS_TEST_DATABASE_URL=postgresql://postgres@{host}:{port}/postgres")
    print(f"ARGUS_DATABASE__URL=postgresql+asyncpg://argus_app:{app}@{host}:{port}/{database}")
    print(
        "ARGUS_DATABASE__MIGRATION_URL="
        f"postgresql+asyncpg://argus_owner:{owner}@{host}:{port}/{database}"
    )
    return 0


def stop(data_dir: Path) -> int:
    import pgserver

    pgserver.get_server(str(data_dir), cleanup_mode="stop")._cleanup()
    print("stopped")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="local PostgreSQL + pgvector (pgserver)")
    parser.add_argument("action", choices=["start", "stop"])
    parser.add_argument("--data", type=Path, required=True, help="data directory")
    parser.add_argument("--database", default="argus")
    args = parser.parse_args()
    if args.action == "start":
        return start(args.data, args.database)
    return stop(args.data)


if __name__ == "__main__":
    sys.exit(main())
