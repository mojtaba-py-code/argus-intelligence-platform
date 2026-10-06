"""Fill a local development database with a demo organisation, to explore the web dashboard.

    python scripts/seed_demo.py            # create the demo data (once)
    python scripts/seed_demo.py --fresh    # purge the demo organisation and create it again

Then start the API (``argus serve``) and open http://localhost:8000/app/.

Development only: the script refuses to run unless ``ARGUS_ENVIRONMENT=development`` and needs
both database URLs (``ARGUS_DATABASE__URL`` and ``ARGUS_DATABASE__MIGRATION_URL``). The demo
user's password is generated on the first run and written to ``.env.demo`` next to this
repository's ``.env`` (git-ignored); the script never prints it.

Real where it can be: the user, organisation, projects, document and research job go through the
public API in-process, and the worker processes the document and runs the research with the
offline local models - the report is a real one. Web monitoring needs the internet, so the
monitor, its pages and the change it found are inserted directly and named "(demo)".
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import secrets
import sys
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx
from asgi_lifespan import LifespanManager
from sqlalchemy import text

from argus.apps.api.main import create_app
from argus.apps.container import Container, build_container
from argus.apps.worker.main import build_worker
from argus.core.config import Environment, Settings, load_settings
from argus.infrastructure.db import Database
from argus.modules.platform.lifecycle import OrganizationLifecycle

ROOT = Path(__file__).resolve().parents[1]
CREDENTIALS = ROOT / ".env.demo"
EMAIL = "demo@example.com"
ORGANISATION = "Demo Research Co"
V1 = "/api/v1"

# Fictional companies. One short document per theme, so the offline analyst (which quotes the
# best-matching sentence of each passage) finds different evidence for each research question.
DOCUMENTS = {
    "market-position.txt": (
        "Helpdesk Alpha holds the strongest market position among customer-support software"
        " vendors, with an estimated 31 percent share in 2026. Supportly is the main challenger:"
        " its market position improved from 9 to 14 percent share in one year. TicketForge keeps"
        " a stable market position of about 11 percent, mostly in regulated industries."
    ),
    "pricing-developments.txt": (
        "The most recent development in pricing: Helpdesk Alpha raised its Team plan to 59"
        " dollars per agent per month in September 2026 and removed the annual discount."
        " Supportly now includes an AI reply assistant in every plan at no extra price."
        " TicketForge pricing is quote-based because it sells an on-premises edition."
    ),
    "risks-and-reviews.txt": (
        "The main risks and criticisms for Helpdesk Alpha are slow onboarding and the recent"
        " price rise. Supportly customers report that AI replies need careful review, an open"
        " problem for regulated customers. TicketForge risks losing smaller customers to cheaper"
        " cloud vendors, although it is the only vendor offering EU data residency."
    ),
}


def _credentials() -> str:
    if CREDENTIALS.exists():
        for line in CREDENTIALS.read_text(encoding="utf-8").splitlines():
            if line.startswith("ARGUS_DEMO_PASSWORD="):
                return line.split("=", 1)[1].strip()
    password = secrets.token_urlsafe(18)
    CREDENTIALS.write_text(
        "# Written by scripts/seed_demo.py - local development only, never commit (git-ignored).\n"
        f"ARGUS_DEMO_EMAIL={EMAIL}\nARGUS_DEMO_PASSWORD={password}\n",
        encoding="utf-8",
    )
    return password


class Api:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client
        self.token = ""

    async def call(self, method: str, path: str, **kwargs: Any) -> Any:
        response = await self.client.request(
            method, V1 + path, headers={"Authorization": f"Bearer {self.token}"}, **kwargs
        )
        if response.status_code >= 400:
            msg = f"{method} {path} -> {response.status_code}: {response.text[:300]}"
            raise RuntimeError(msg)
        return response.json() if response.content else None


async def _ensure_user(container: Container, password: str) -> None:
    async with container.database.session() as session:
        exists = (
            await session.execute(text("SELECT 1 FROM users WHERE email = :e"), {"e": EMAIL})
        ).first()
    if exists is None:
        await container.auth.create_user(
            email=EMAIL, password=password, full_name="Demo Analyst", verified=True
        )


async def _purge_existing(api: Api, owner: Database, container: Container) -> None:
    for org in await api.call("GET", "/orgs"):
        if org["name"] == ORGANISATION:
            lifecycle = OrganizationLifecycle(
                owner,
                container.audit,
                container.storage,
                container.clock,
                container.settings.platform,
            )
            await api.call("DELETE", f"/orgs/{org['id']}")
            await lifecycle.purge(UUID(org["id"]), force=True)
            print(f"purged the previous demo organisation {org['id']}")


async def _monitoring(owner: Database, org: UUID, project: UUID, user: UUID) -> None:
    """A monitor that watched a (fictional) pricing page and found a change."""
    url = "https://helpdesk-alpha.example/pricing"
    source, before, after = uuid4(), uuid4(), uuid4()
    monitor, target = uuid4(), uuid4()
    pages = {
        before: (
            "Team plan: 49 dollars per agent per month. Save 15 percent with annual billing.",
            3,
        ),
        after: ("Team plan: 59 dollars per agent per month.", 0),
    }
    async with owner.session() as session:
        await session.execute(
            text(
                "INSERT INTO sources (id, organization_id, project_id, url, url_hash, domain, status,"
                " title, trust_tier, reputation, discovered_via, last_fetched_at, fetch_count)"
                " VALUES (:id, :org, :project, :url, :hash, 'helpdesk-alpha.example', 'fetched',"
                " 'Helpdesk Alpha pricing (demo)', 'medium', 0.6, 'monitor', now(), 2)"
            ),
            {
                "id": source,
                "org": org,
                "project": project,
                "url": url,
                "hash": hashlib.sha256(url.encode()).digest(),
            },
        )
        for snapshot, (page, days) in pages.items():
            await session.execute(
                text(
                    "INSERT INTO source_snapshots (id, organization_id, source_id, fetched_at,"
                    " last_seen_at, final_url, http_status, media_type, content_hash, byte_size,"
                    " title, text) VALUES (:id, :org, :source, now() - make_interval(days => :days),"
                    " now() - make_interval(days => :days), :url, 200, 'text/html', :hash, :size,"
                    " 'Pricing', :text)"
                ),
                {
                    "id": snapshot,
                    "org": org,
                    "source": source,
                    "days": days,
                    "url": url,
                    "hash": hashlib.sha256(page.encode()).digest(),
                    "size": len(page),
                    "text": page,
                },
            )
        for domain, status, level in (
            ("tracker.example", "blocked", "none"),
            ("free-reviews.example", "fetched", "high"),
        ):
            other = f"https://{domain}/"
            await session.execute(
                text(
                    "INSERT INTO sources (id, organization_id, project_id, url, url_hash, domain,"
                    " status, title, trust_tier, injection_level, discovered_via)"
                    " VALUES (:id, :org, :project, :url, :hash, :domain, :status, :title, 'low',"
                    " :level, 'search')"
                ),
                {
                    "id": uuid4(),
                    "org": org,
                    "project": project,
                    "url": other,
                    "hash": hashlib.sha256(other.encode()).digest(),
                    "domain": domain,
                    "status": status,
                    "level": level,
                    "title": f"{domain} (demo)",
                },
            )
        await session.execute(
            text(
                "INSERT INTO monitors (id, organization_id, project_id, name, kind, queries, topics,"
                " interval_minutes, significance_threshold, next_run_at, status, last_run_at,"
                " created_by_user_id) VALUES (:id, :org, :project,"
                " 'Competitor pricing pages (demo)', 'urls', '{}', '{pricing}', 1440, 0.4,"
                " now() + interval '7 days', 'active', now(), :user)"
            ),
            {"id": monitor, "org": org, "project": project, "user": user},
        )
        await session.execute(
            text(
                "INSERT INTO monitor_targets (id, organization_id, monitor_id, url, source_id,"
                " last_snapshot_id, last_checked_at) VALUES (:id, :org, :monitor, :url, :source,"
                " :snapshot, now())"
            ),
            {
                "id": target,
                "org": org,
                "monitor": monitor,
                "url": url,
                "source": source,
                "snapshot": after,
            },
        )
        await session.execute(
            text(
                "INSERT INTO monitor_changes (id, organization_id, monitor_id, target_id, snapshot_id,"
                " previous_snapshot_id, topics, significance, summary, diff, status) VALUES (:id,"
                " :org, :monitor, :target, :after, :before, '{pricing}', 0.72, :summary,"
                " CAST(:diff AS jsonb), 'new')"
            ),
            {
                "id": uuid4(),
                "org": org,
                "monitor": monitor,
                "target": target,
                "after": after,
                "before": before,
                "summary": "Team plan price rose from 49 to 59 dollars per agent; the annual"
                " discount was removed.",
                "diff": json.dumps(
                    {
                        "removed": ["49 dollars", "Save 15 percent with annual billing."],
                        "added": ["59 dollars"],
                    }
                ),
            },
        )
        await session.execute(
            text(
                "INSERT INTO notifications (id, organization_id, user_id, event, title, body)"
                " VALUES (:id, :org, :user, 'monitor.change.detected',"
                " 'Competitor pricing pages (demo) found a change',"
                " 'A significant change was detected on a monitored page.')"
            ),
            {"id": uuid4(), "org": org, "user": user},
        )


async def seed(settings: Settings, *, fresh: bool) -> int:
    password = _credentials()
    container = build_container(settings, role="cli")
    assert settings.database.migration_url is not None
    owner = Database(
        settings.database.model_copy(update={"url": settings.database.migration_url}),
        application_name="argus-seed-demo",
    )
    app = create_app(settings, container=container)
    try:
        await _ensure_user(container, password)
        async with (
            LifespanManager(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://localhost"
            ) as client,
        ):
            api = Api(client)
            login = await client.post(
                f"{V1}/auth/login", json={"email": EMAIL, "password": password}
            )
            if login.status_code != 200 or "access_token" not in login.json():
                print("error: cannot sign in as the demo user (see .env.demo)", file=sys.stderr)
                return 1
            api.token = login.json()["access_token"]
            if fresh:
                await _purge_existing(api, owner, container)
            elif any(org["name"] == ORGANISATION for org in await api.call("GET", "/orgs")):
                print("the demo organisation exists already; use --fresh to recreate it")
                return 0

            me = await api.call("GET", "/auth/me")
            org = await api.call("POST", "/orgs", json={"name": ORGANISATION})
            orgs = f"/orgs/{org['id']}"
            market = await api.call(
                "POST",
                f"{orgs}/projects",
                json={"name": "Support software market", "description": "Competitive research"},
            )
            await api.call(
                "POST",
                f"{orgs}/projects",
                json={"name": "Board matters", "visibility": "restricted"},
            )
            base = f"{orgs}/projects/{market['id']}"
            for name, body in DOCUMENTS.items():
                await api.call(
                    "POST",
                    f"{base}/documents",
                    files={"file": (name, body.encode(), "text/plain")},
                )
            await build_worker(container, queues=("documents", "default")).run_until_idle()
            job = await api.call(
                "POST",
                f"{base}/research-jobs",
                json={
                    "title": "Customer-support software landscape",
                    "objective": "Compare the market position, pricing and risks of"
                    " customer-support software vendors.",
                    "mode": "documents",
                },
            )
            await build_worker(container, queues=("research", "default")).run_until_idle()
            finished = await api.call("GET", f"{base}/research-jobs/{job['id']}")
            # One more job, left in the queue, so the dashboard shows active work.
            await api.call(
                "POST",
                f"{base}/research-jobs",
                json={
                    "title": "EU data residency options",
                    "objective": "Which vendors offer EU data residency, and on which plans?",
                    "mode": "documents",
                },
            )
            await _monitoring(owner, UUID(org["id"]), UUID(market["id"]), UUID(me["id"]))
        print(f"seeded {ORGANISATION} ({org['id']}); research job {finished['status']}")
        print(
            f"sign in at {settings.http.public_base_url}app/ with the credentials in {CREDENTIALS}"
        )
        return 0
    finally:
        await owner.dispose()
        await container.aclose()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--fresh", action="store_true", help="purge the demo organisation first")
    args = parser.parse_args()
    settings = load_settings()
    if settings.environment is not Environment.DEVELOPMENT:
        print("error: development only (ARGUS_ENVIRONMENT=development)", file=sys.stderr)
        return 2
    if settings.database.migration_url is None:
        print("error: set ARGUS_DATABASE__MIGRATION_URL (the owner role)", file=sys.stderr)
        return 2
    return asyncio.run(seed(settings, fresh=args.fresh))


if __name__ == "__main__":
    raise SystemExit(main())
