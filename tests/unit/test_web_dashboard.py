"""Phase 24: the web dashboard is served safely and its code keeps the rules its CSP enforces.

Three layers. The server side: four allow-listed files, the dashboard's own
Content-Security-Policy, no path from the request reaching the file system. The page's code,
statically: the script renders text only, keeps tokens in memory, talks to its own API, and the
HTML carries no inline code (enforced by Trusted Types and the CSP in the browser). The page's
behaviour: ``tests/web/dashboard.test.mjs`` runs the script in Node against the real page with a
scripted API - sign-in and sign-out, token refresh, the back/forward cache, late answers, idle
sign-out and focus.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import AsyncIterator
from html.parser import HTMLParser
from importlib.resources import files
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager

from argus.apps.api.main import create_app
from argus.apps.api.middleware import WEB_CSP
from argus.apps.container import build_container
from argus.apps.web.router import MEDIA_TYPES, PREFIX, etag_matches
from tests.support import make_settings

STATIC = Path(str(files("argus.apps.web").joinpath("static")))
BEHAVIOUR = Path(__file__).resolve().parents[1] / "web" / "dashboard.test.mjs"
NODE = shutil.which("node")


def read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def code_without_comments(source: str) -> str:
    """The script with comments removed (they explain the rules, so they name the sinks)."""
    without_blocks = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return "\n".join(
        line for line in without_blocks.splitlines() if not line.lstrip().startswith("//")
    )


class Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.script_bodies: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))
        self._in_script = tag == "script"

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self.script_bodies.append(data)


def page() -> Page:
    parsed = Page()
    parsed.feed(read("index.html"))
    return parsed


# --------------------------------------------------------------------------- the files
def test_only_the_allow_listed_files_ship() -> None:
    assert sorted(p.name for p in STATIC.iterdir()) == sorted(MEDIA_TYPES)


FORBIDDEN_IN_SCRIPT = {
    "HTML sinks": r"\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write|"
    r"createContextualFragment|DOMParser|\.srcdoc",
    "code from strings": r"\beval\s*\(|new\s+Function\b|\bFunction\s*\(|"
    r"set(?:Timeout|Interval)\s*\(\s*['\"`]|import\s*\(",
    "persistent storage": r"localStorage|sessionStorage|indexedDB|document\.cookie|caches\.",
    "other channels": r"XMLHttpRequest|WebSocket|EventSource|postMessage|window\.open|"
    r"navigator\.sendBeacon",
    "navigation from data": r"location\s*=|location\.(?:href|assign|replace)\s*[=(]|javascript:",
    "absolute URLs": r"https?://",
}


@pytest.mark.parametrize("rule", sorted(FORBIDDEN_IN_SCRIPT))
def test_the_script_keeps_its_rules(rule: str) -> None:
    code = code_without_comments(read("app.js"))
    found = re.findall(FORBIDDEN_IN_SCRIPT[rule], code)
    assert not found, f"{rule}: {found}"


def test_requests_go_only_to_this_origins_api() -> None:
    code = code_without_comments(read("app.js"))
    assert 'const API = new URL("../api/v1/", window.location.href);' in code
    calls = re.findall(r"\bfetch\(", code)
    to_api = re.findall(r'\bfetch\(new URL\((?:path|"auth/logout"), API\), \{', code)
    assert calls
    assert len(to_api) == len(calls)
    assert code.count('credentials: "omit"') == len(calls)
    assert 'redirect: "error"' in code


def function_body(code: str, name: str) -> str:
    start = code.index(f"function {name}(")
    return code[start : code.index("\n}\n", start)]


def test_links_are_built_only_for_web_urls() -> None:
    code = code_without_comments(read("app.js"))
    # One place creates anchors, and it checks the scheme first.
    assert code.count('el("a"') == 1
    safe_link = function_body(code, "safeLink")
    assert 'el("a"' in safe_link
    assert 'parsed.protocol !== "https:" && parsed.protocol !== "http:"' in safe_link
    assert 'rel: "noopener noreferrer nofollow"' in safe_link


def test_every_element_the_script_uses_exists_once() -> None:
    html = read("index.html")
    code = code_without_comments(read("app.js"))
    ids = re.findall(r'\sid="([^"]+)"', html)
    assert len(ids) == len(set(ids)), "duplicate ids"
    used = set(re.findall(r'(?:byId|say)\("([a-z-]+)"', code))
    used |= set(re.findall(r'"((?:view-[a-z]+)|loading)"', code))
    assert used, "the script uses no elements?"
    assert used <= set(ids), sorted(used - set(ids))


def test_the_page_carries_no_inline_code_or_style() -> None:
    parsed = page()
    assert all(not body.strip() for body in parsed.script_bodies), "inline script"
    scripts = [attrs for tag, attrs in parsed.tags if tag == "script"]
    assert scripts == [{"type": "module", "src": "app.js"}]
    for tag, attrs in parsed.tags:
        assert tag != "style", "inline <style>"
        assert "style" not in attrs, f"style attribute on <{tag}>"
        handlers = [name for name in attrs if name.startswith("on")]
        assert not handlers, f"inline handler {handlers} on <{tag}>"
        for name in ("src", "href", "action", "formaction"):
            value = attrs.get(name)
            if value is None:
                continue
            assert value in MEDIA_TYPES or value.startswith("#"), f"<{tag} {name}={value!r}>"


def test_forms_never_submit_secrets_in_a_url() -> None:
    forms = [attrs for tag, attrs in page().tags if tag == "form"]
    assert forms
    assert all(attrs.get("method") == "post" and "action" not in attrs for attrs in forms)
    passwords = [attrs for tag, attrs in page().tags if attrs.get("type") == "password"]
    assert [attrs.get("autocomplete") for attrs in passwords] == ["current-password"]


def test_the_stylesheet_loads_nothing() -> None:
    css = read("app.css")
    assert not re.search(r"@import|url\(|expression\(|behavior\s*:", css, re.IGNORECASE)


def test_the_icon_is_inert() -> None:
    svg = read("icon.svg")
    assert not re.search(r"<script|\son\w+=|href=|<foreignObject", svg, re.IGNORECASE)


# ---------------------------------------------------------------------------- behaviour
@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_the_page_behaves() -> None:
    assert NODE is not None
    result = subprocess.run(
        [NODE, "--test", str(BEHAVIOUR)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-2000:]


# -------------------------------------------------------------------------- serving it
async def _client(*, web_dashboard: bool = True) -> AsyncIterator[httpx.AsyncClient]:
    settings = make_settings(http={"web_dashboard": web_dashboard})
    container = build_container(settings, role="api")
    app = create_app(settings, container=container)
    transport = httpx.ASGITransport(app=app)
    async with (
        LifespanManager(app),
        httpx.AsyncClient(transport=transport, base_url="http://testserver") as client,
    ):
        yield client
    await container.aclose()


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async for c in _client():
        yield c


async def test_the_dashboard_is_served_with_its_own_policy(client: httpx.AsyncClient) -> None:
    home = await client.get("/")
    assert home.status_code == 307
    assert home.headers["location"] == PREFIX + "/"
    redirect = await client.get(PREFIX)
    assert redirect.status_code == 308
    assert redirect.headers["location"] == PREFIX + "/"

    response = await client.get(PREFIX + "/")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert response.headers["content-security-policy"] == WEB_CSP
    assert "require-trusted-types-for 'script'" in WEB_CSP
    assert "'unsafe-inline'" not in WEB_CSP
    assert "'unsafe-eval'" not in WEB_CSP
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-cache"
    assert '<script type="module" src="app.js"></script>' in response.text

    script = await client.get(PREFIX + "/app.js")
    assert script.headers["content-type"] == "text/javascript; charset=utf-8"
    assert script.headers["content-security-policy"] == WEB_CSP
    etag = script.headers["etag"]
    for condition in (etag, f"W/{etag}", f'"other", W/{etag}', "*"):
        unchanged = await client.get(PREFIX + "/app.js", headers={"If-None-Match": condition})
        assert unchanged.status_code == 304, condition
        assert unchanged.content == b""
    changed = await client.get(PREFIX + "/app.js", headers={"If-None-Match": '"other"'})
    assert changed.status_code == 200


def test_if_none_match_is_compared_weakly() -> None:
    assert etag_matches('W/"a", "b"', '"a"')
    assert etag_matches("*", '"a"')
    assert not etag_matches('"b"', '"a"')
    assert not etag_matches(None, '"a"')
    assert not etag_matches("", '"a"')


@pytest.mark.parametrize(
    "path",
    [
        "/app/index.html",
        "/app/unknown.js",
        "/app/..%2Fpyproject.toml",
        "/app/%2e%2e/router.py",
        "/app/static/app.js",
        "/app/router.py",
        "/app/APP.JS",
    ],
)
async def test_nothing_else_is_reachable(client: httpx.AsyncClient, path: str) -> None:
    response = await client.get(path)
    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"


async def test_the_api_keeps_its_stricter_policy(client: httpx.AsyncClient) -> None:
    response = await client.get("/health/live")
    assert response.headers["content-security-policy"].startswith("default-src 'none'")
    assert "script-src" not in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"


async def test_the_dashboard_can_be_switched_off() -> None:
    async for client in _client(web_dashboard=False):
        assert (await client.get(PREFIX + "/")).status_code == 404
        assert (await client.get("/")).status_code == 404
