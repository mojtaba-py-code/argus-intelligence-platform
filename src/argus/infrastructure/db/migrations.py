"""Programmatic Alembic access for the CLI, the readiness probe and the test-suite."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from argus.core.config import Settings


def script_location() -> Path:
    """Migrations ship inside the wheel as ``argus/_migrations``; in a checkout they live at the
    repository root."""
    packaged = resources.files("argus").joinpath("_migrations")
    if packaged.is_dir():
        return Path(str(packaged))
    repo = Path(__file__).resolve().parents[4] / "migrations"
    if repo.is_dir():
        return repo
    msg = "cannot locate the Alembic migrations directory"  # pragma: no cover
    raise FileNotFoundError(msg)  # pragma: no cover


def alembic_config(settings: Settings) -> Config:
    config = Config()
    config.set_main_option("script_location", str(script_location()))
    config.attributes["settings"] = settings
    return config


@lru_cache(maxsize=1)
def head_revision() -> str | None:
    script = ScriptDirectory(str(script_location()))
    return script.get_current_head()


@lru_cache(maxsize=1)
def known_revisions() -> frozenset[str]:
    """Every revision this build ships (its head and all its ancestors)."""
    script = ScriptDirectory(str(script_location()))
    return frozenset(revision.revision for revision in script.walk_revisions())


def schema_state(current: str | None) -> str:
    """``ok`` when the database is at this build's head, or ahead of it - a newer release has
    migrated, and migrations stay backward compatible for one release, so this build still runs
    (rolling updates keep the old pods serving). ``pending`` when the database is behind: this
    build needs a migration that has not run yet."""
    if current == head_revision():
        return "ok"
    if current is not None and current not in known_revisions():
        return "ok"
    return "pending"
