"""RFC 9457 problem documents and the exception handlers that produce them.

Clients always receive ``application/problem+json`` with a stable ``code`` and the request id.
They never receive stack traces, SQL, file paths, provider names, or echoed input values - the
validation handler deliberately drops Pydantic's ``input`` member, which would otherwise reflect
whatever the client sent (including passwords) back into responses and logs.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response
from starlette.types import Send

from argus.core import context
from argus.core.errors import ArgusError, PermissionDenied, RateLimited
from argus.core.logging import get_logger

PROBLEM_MEDIA_TYPE = "application/problem+json"
DenialHook = Callable[[Request, PermissionDenied], Awaitable[None]]
_MAX_VALIDATION_ERRORS = 20
log = get_logger(__name__)


def problem_body(
    *,
    status: int,
    code: str,
    title: str,
    detail: str,
    type_base: str,
    instance: str | None = None,
    extensions: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "type": f"{type_base}{code}",
        "title": title,
        "status": status,
        "detail": detail,
        "code": code,
    }
    if instance:
        body["instance"] = instance
    request_id = context.get("request_id")
    if request_id:
        body["request_id"] = request_id
    for key, value in (extensions or {}).items():
        body.setdefault(key, value)
    return body


def problem_response(body: dict[str, Any], *, headers: Mapping[str, str] | None = None) -> Response:
    return Response(
        content=json.dumps(body, separators=(",", ":"), ensure_ascii=False),
        status_code=int(body["status"]),
        media_type=PROBLEM_MEDIA_TYPE,
        headers=dict(headers or {}),
    )


async def send_problem(
    send: Send,
    *,
    status: int,
    code: str,
    title: str,
    detail: str,
    type_base: str,
    headers: Sequence[tuple[bytes, bytes]] = (),
) -> None:
    """Emit a problem response directly from pure-ASGI middleware."""
    payload = json.dumps(
        problem_body(status=status, code=code, title=title, detail=detail, type_base=type_base),
        separators=(",", ":"),
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", PROBLEM_MEDIA_TYPE.encode()),
                (b"content-length", str(len(payload)).encode()),
                *headers,
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


def _type_base(request: Request) -> str:
    container = getattr(request.app.state, "container", None)
    if container is not None:
        base: str = container.settings.http.problem_type_base
        return base
    return "urn:argus:problem:"


def _sanitise_validation_errors(errors: Sequence[Any]) -> list[dict[str, Any]]:
    cleaned: list[dict[str, Any]] = []
    for error in list(errors)[:_MAX_VALIDATION_ERRORS]:
        if not isinstance(error, Mapping):
            continue
        loc = [str(part) for part in error.get("loc", ())][:8]
        cleaned.append(
            {
                "loc": loc,
                "msg": str(error.get("msg", "invalid value"))[:200],
                "type": str(error.get("type", "value_error"))[:64],
            }
        )
    return cleaned


def install_exception_handlers(
    app: FastAPI, *, on_permission_denied: DenialHook | None = None
) -> None:
    """``on_permission_denied`` is awaited for every 403 ``permission_denied`` (the audit trail
    of members' refused actions); it is best-effort and can never change the response."""

    @app.exception_handler(ArgusError)
    async def _argus_error(request: Request, exc: ArgusError) -> Response:
        level = "error" if exc.status >= 500 else "info"
        getattr(log, level)("request.failed", code=exc.code, status=exc.status, **exc.log_context)
        if on_permission_denied is not None and isinstance(exc, PermissionDenied):
            try:
                await on_permission_denied(request, exc)
            except Exception as hook_error:  # noqa: BLE001 - the 403 must still be returned
                log.error("audit.denial_hook_failed", error_type=type(hook_error).__name__)
        headers: dict[str, str] = {}
        if isinstance(exc, RateLimited):
            headers["Retry-After"] = str(max(1, int(exc.retry_after_s + 0.999)))
        if exc.status == 401:
            headers["WWW-Authenticate"] = 'Bearer realm="argus"'
        return problem_response(
            problem_body(
                status=exc.status,
                code=exc.code,
                title=exc.title,
                detail=exc.detail,
                type_base=_type_base(request),
                instance=request.url.path,
                extensions=exc.extensions,
            ),
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> Response:
        return problem_response(
            problem_body(
                status=422,
                code="validation_failed",
                title="Validation failed",
                detail="The request is not valid.",
                type_base=_type_base(request),
                instance=request.url.path,
                extensions={"errors": _sanitise_validation_errors(exc.errors())},
            )
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> Response:
        status = exc.status_code
        phrase = HTTPStatus(status).phrase if status in HTTPStatus._value2member_map_ else "Error"
        code = {
            400: "bad_request",
            401: "authentication_required",
            403: "permission_denied",
            404: "not_found",
            405: "method_not_allowed",
            413: "payload_too_large",
            415: "unsupported_media_type",
        }.get(status, phrase.lower().replace(" ", "_").replace("-", "_"))
        detail = str(exc.detail) if status < 500 else phrase
        if status == 404:
            detail = "The resource does not exist or you do not have access to it."
        return problem_response(
            problem_body(
                status=status,
                code=code,
                title=phrase,
                detail=detail,
                type_base=_type_base(request),
                instance=request.url.path,
            ),
            headers=dict(exc.headers or {}),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> Response:
        log.error("request.unhandled_exception", error_type=type(exc).__name__, exc_info=exc)
        return problem_response(
            problem_body(
                status=500,
                code="internal_error",
                title="Internal server error",
                detail="The request could not be completed.",
                type_base=_type_base(request),
                instance=request.url.path,
            )
        )
