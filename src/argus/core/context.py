"""Per-request / per-job diagnostic context carried in :mod:`contextvars`.

The values are *diagnostic only* (they feed logs, traces and audit records). Authorisation never
reads them: security decisions use the explicit ``Principal`` / ``TenantScope`` objects passed
through function arguments, which cannot be changed by a stray ``bind()`` somewhere else.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from contextvars import ContextVar, Token
from typing import Any, Final

_FIELDS: Final = (
    "request_id",
    "client_ip",
    "user_id",
    "organization_id",
    "project_id",
    "job_id",
    "agent_run_id",
    "tool_call_id",
    "worker_id",
)

_VARS: Final[dict[str, ContextVar[str | None]]] = {
    name: ContextVar(f"argus_{name}", default=None) for name in _FIELDS
}


def get(name: str) -> str | None:
    return _VARS[name].get()


def snapshot() -> dict[str, str]:
    """All context fields that are currently set."""
    return {name: value for name, var in _VARS.items() if (value := var.get()) is not None}


@contextlib.contextmanager
def bind(**values: Any) -> Iterator[None]:
    """Bind fields for the duration of a ``with`` block (restored afterwards, task-safe)."""
    tokens: list[tuple[ContextVar[str | None], Token[str | None]]] = []
    try:
        for name, value in values.items():
            var = _VARS[name]  # KeyError on unknown field names is intentional
            tokens.append((var, var.set(None if value is None else str(value))))
        yield
    finally:
        for var, token in reversed(tokens):
            var.reset(token)


def set_value(name: str, value: Any) -> None:
    """Set a field for the rest of the current context (used by middleware at request start)."""
    _VARS[name].set(None if value is None else str(value))
