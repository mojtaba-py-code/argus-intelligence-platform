"""Shared FastAPI dependencies."""

from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import Depends, Query, Request
from fastapi.dependencies.models import Dependant
from pydantic import BaseModel

from argus.apps.container import Container
from argus.core.errors import ValidationFailed
from argus.core.pagination import DEFAULT_PAGE_SIZE, MAX_CURSOR_CHARS, MAX_PAGE_SIZE, PageQuery

# Keyed by id(route): FastAPI's Dependant objects are unhashable, so functools caches cannot be
# used here (they fail at runtime, not at type-check time).
_ALLOWED_QUERY: dict[int, frozenset[str]] = {}
_UNSAFE = re.compile(r"[^A-Za-z0-9_.\-\[\]]")


def get_container(request: Request) -> Container:
    container: Container = request.app.state.container
    return container


def page_params(
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    cursor: Annotated[str | None, Query(max_length=MAX_CURSOR_CHARS)] = None,
) -> PageQuery:
    """Keyset pagination parameters for every listing endpoint (a dependency rather than a query
    model: FastAPI expands a model only when it is a route's *only* query parameter)."""
    return PageQuery(limit=limit, cursor=cursor)


PageDep = Annotated[PageQuery, Depends(page_params)]


def _collect_query_names(dependant: Dependant, names: set[str]) -> None:
    for param in dependant.query_params:
        annotation = getattr(param.field_info, "annotation", None)
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            for field_name, field in annotation.model_fields.items():
                names.add(field.alias or field_name)
        else:
            names.add(param.alias)
            names.add(param.name)
    for sub in dependant.dependencies:
        _collect_query_names(sub, names)


def _allowed_query_names(route: Any) -> frozenset[str]:
    cached = _ALLOWED_QUERY.get(id(route))
    if cached is None:
        dependant = getattr(route, "dependant", None)
        names: set[str] = set()
        if isinstance(dependant, Dependant):
            _collect_query_names(dependant, names)
        cached = frozenset(names)
        _ALLOWED_QUERY[id(route)] = cached
    return cached


async def reject_unknown_query_parameters(request: Request) -> None:
    """422 for query parameters the route does not declare.

    Silently ignoring an unknown parameter turns a client typo (``?limt=5``) or a probing attempt
    into a request that "works" with defaults; failing loudly is safer and easier to debug.
    """
    if not request.query_params:
        return
    allowed = _allowed_query_names(request.scope.get("route"))
    unknown = sorted({name for name in request.query_params if name not in allowed})
    if unknown:
        # Names are reduced to a safe alphabet: the response must not reflect arbitrary input.
        shown = ", ".join(_UNSAFE.sub("?", name[:40]) for name in unknown[:10])
        raise ValidationFailed(f"Unknown query parameter(s): {shown}.")
