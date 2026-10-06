"""Serves the web dashboard: four static files from an allow-list, read once at start-up.

The page is a client of the public JSON API on the same origin, with the same rules as any other
client: a bearer token (kept in the page's memory only - never in storage or cookies, so there is
nothing for CSRF to ride on and nothing left behind after the tab closes), the same
authorisation on every request, the same audit trail.

What keeps the page itself safe is mostly in its Content-Security-Policy
(``argus.apps.api.middleware.WEB_CSP``): only these same-origin files may load, no inline script
or style, no connections to other origins, no framing, and Trusted Types enforced - so even a
mistaken ``innerHTML`` in the script would throw instead of rendering markup. The script renders
every value with ``textContent``; ``tests/unit/test_web_dashboard.py`` checks both.

No path parameter reaches the file system: a request names a key of an in-memory dict.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from importlib.resources import files
from typing import Final

from fastapi import APIRouter, Request, Response
from fastapi.responses import RedirectResponse

from argus.core.errors import NotFound

PREFIX: Final = "/app"
INDEX: Final = "index.html"
MEDIA_TYPES: Final[dict[str, str]] = {
    INDEX: "text/html; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
    "app.css": "text/css; charset=utf-8",
    "icon.svg": "image/svg+xml",
}


def etag_matches(if_none_match: str | None, etag: str) -> bool:
    """RFC 9110 ``If-None-Match``: a list of tags compared weakly (a proxy that compresses the
    response marks the tag weak with ``W/``), or ``*``."""
    if not if_none_match:
        return False
    tags = {tag.strip().removeprefix("W/") for tag in if_none_match.split(",")}
    return "*" in tags or etag in tags


@dataclass(frozen=True)
class Asset:
    body: bytes
    media_type: str
    etag: str


def load_assets() -> dict[str, Asset]:
    static = files(__package__ or "argus.apps.web").joinpath("static")
    assets: dict[str, Asset] = {}
    for name, media_type in MEDIA_TYPES.items():
        body = static.joinpath(name).read_bytes()
        assets[name] = Asset(body, media_type, f'"{hashlib.sha256(body).hexdigest()[:32]}"')
    return assets


def build_router() -> APIRouter:
    assets = load_assets()
    router = APIRouter(include_in_schema=False)

    def serve(name: str, request: Request) -> Response:
        asset = assets.get(name)
        if asset is None:
            raise NotFound
        # Revalidate every time (the files change with each release); the ETag keeps it cheap.
        headers = {"ETag": asset.etag, "Cache-Control": "no-cache"}
        if etag_matches(request.headers.get("if-none-match"), asset.etag):
            return Response(status_code=304, headers=headers)
        return Response(asset.body, media_type=asset.media_type, headers=headers)

    @router.get("/")
    async def home() -> RedirectResponse:
        return RedirectResponse(PREFIX + "/", status_code=307)

    @router.get(PREFIX)
    async def without_slash() -> RedirectResponse:
        # The page loads its files by relative URL, which needs the trailing slash.
        return RedirectResponse(PREFIX + "/", status_code=308)

    @router.get(PREFIX + "/")
    async def index(request: Request) -> Response:
        return serve(INDEX, request)

    @router.get(PREFIX + "/{name}")
    async def asset(name: str, request: Request) -> Response:
        if name == INDEX:  # one address per file
            raise NotFound
        return serve(name, request)

    return router
