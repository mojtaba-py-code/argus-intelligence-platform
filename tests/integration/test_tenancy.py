"""Phase 3: organisations, members, invitations, projects, service accounts and API keys."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from argus.core.config import Settings
from argus.security import totp
from tests.support import (
    STRONG_PASSWORD,
    ApiHarness,
    api_harness,
    bearer,
    create_org,
    join_org,
    register_and_login,
    token_from_email,
    unique_email,
)

pytestmark = pytest.mark.integration
V1 = "/api/v1"


@pytest.fixture
async def h(db_settings: Settings) -> AsyncIterator[ApiHarness]:
    async with api_harness(db_settings) as harness:
        yield harness


_org = create_org
_join = join_org


# ------------------------------------------------------------------------- organisations
async def test_creator_becomes_owner_and_can_configure(h: ApiHarness) -> None:
    _, tokens = await register_and_login(h)
    owner = tokens["access_token"]
    org = await _org(h, owner)
    assert org["role"] == "owner"
    assert len(org["slug"]) >= 3
    listing = await h.client.get(f"{V1}/orgs", headers=bearer(owner))
    assert [o["id"] for o in listing.json()] == [org["id"]]
    updated = await h.client.patch(
        f"{V1}/orgs/{org['id']}",
        json={
            "name": "Acme Intelligence",
            "budgets": {"monthly_llm_usd": 250, "job_default_usd": 3, "approval_threshold_usd": 15},
        },
        headers=bearer(owner),
    )
    assert updated.status_code == 200
    assert updated.json()["settings"]["budgets"]["monthly_llm_usd"] == 250


async def test_duplicate_slug_conflicts(h: ApiHarness) -> None:
    _, tokens = await register_and_login(h)
    slug = f"acme-{unique_email()[:8].replace('.', '')}"
    first = await h.client.post(
        f"{V1}/orgs", json={"name": "A", "slug": slug}, headers=bearer(tokens["access_token"])
    )
    assert first.status_code == 201
    second = await h.client.post(
        f"{V1}/orgs", json={"name": "B", "slug": slug}, headers=bearer(tokens["access_token"])
    )
    assert second.status_code == 409


@pytest.mark.parametrize("slug", ["ab", "-abc", "abc-", "a_b_c", "a--b", "admin", "x" * 49])
async def test_invalid_or_reserved_slugs_are_rejected(h: ApiHarness, slug: str) -> None:
    _, tokens = await register_and_login(h)
    response = await h.client.post(
        f"{V1}/orgs", json={"name": "X", "slug": slug}, headers=bearer(tokens["access_token"])
    )
    assert response.status_code == 422


# ------------------------------------------------------------------------ invitations
async def test_invitation_flow_and_role_limits(h: ApiHarness) -> None:
    _, tokens = await register_and_login(h)
    owner = tokens["access_token"]
    org = await _org(h, owner)
    _, admin = await _join(h, owner, org["id"], "admin")
    _, analyst = await _join(h, owner, org["id"], "analyst")

    as_admin = await h.client.post(
        f"{V1}/orgs/{org['id']}/invitations",
        json={"email": unique_email(), "role": "owner"},
        headers=bearer(admin),
    )
    assert as_admin.status_code == 403  # cannot invite above own role
    as_analyst = await h.client.post(
        f"{V1}/orgs/{org['id']}/invitations",
        json={"email": unique_email(), "role": "viewer"},
        headers=bearer(analyst),
    )
    assert as_analyst.status_code == 403
    members = await h.client.get(f"{V1}/orgs/{org['id']}/members", headers=bearer(analyst))
    assert sorted(m["role"] for m in members.json()) == ["admin", "analyst", "owner"]


async def test_invitation_cannot_be_hijacked_or_reused(h: ApiHarness) -> None:
    _, tokens = await register_and_login(h)
    owner = tokens["access_token"]
    org = await _org(h, owner)
    invited = unique_email("invitee")
    await h.client.post(
        f"{V1}/orgs/{org['id']}/invitations",
        json={"email": invited, "role": "viewer"},
        headers=bearer(owner),
    )
    invitation_token = token_from_email(h.mailer.last_to(invited).text)

    _, intruder_tokens = await register_and_login(h)  # somebody else got hold of the link
    intruder = intruder_tokens["access_token"]
    hijack = await h.client.post(
        f"{V1}/invitations/accept", json={"token": invitation_token}, headers=bearer(intruder)
    )
    assert hijack.status_code == 403

    _, rightful = await register_and_login(h, invited)
    ok = await h.client.post(
        f"{V1}/invitations/accept",
        json={"token": invitation_token},
        headers=bearer(rightful["access_token"]),
    )
    assert ok.status_code == 200
    again = await h.client.post(
        f"{V1}/invitations/accept",
        json={"token": invitation_token},
        headers=bearer(rightful["access_token"]),
    )
    assert again.status_code == 422


# ----------------------------------------------------------------------------- members
async def test_role_change_rules(h: ApiHarness) -> None:
    owner_email, tokens = await register_and_login(h)
    owner = tokens["access_token"]
    org = await _org(h, owner)
    me = (await h.client.get(f"{V1}/auth/me", headers=bearer(owner))).json()
    _, admin = await _join(h, owner, org["id"], "admin")
    analyst_email, _ = await _join(h, owner, org["id"], "analyst")
    members = {
        m["email"]: m["user_id"]
        for m in (
            await h.client.get(f"{V1}/orgs/{org['id']}/members", headers=bearer(owner))
        ).json()
    }

    own = await h.client.patch(
        f"{V1}/orgs/{org['id']}/members/{me['id']}", json={"role": "admin"}, headers=bearer(owner)
    )
    assert own.status_code == 403  # nobody changes their own role
    grant_owner = await h.client.patch(
        f"{V1}/orgs/{org['id']}/members/{members[analyst_email]}",
        json={"role": "owner"},
        headers=bearer(admin),
    )
    assert grant_owner.status_code == 403  # only owners grant ownership
    promote = await h.client.patch(
        f"{V1}/orgs/{org['id']}/members/{members[analyst_email]}",
        json={"role": "admin"},
        headers=bearer(owner),
    )
    assert promote.status_code == 204
    leave_last_owner = await h.client.delete(
        f"{V1}/orgs/{org['id']}/members/{me['id']}", headers=bearer(owner)
    )
    assert leave_last_owner.status_code == 409
    assert owner_email


async def test_removed_member_loses_access_and_keys(h: ApiHarness) -> None:
    _, tokens = await register_and_login(h)
    owner = tokens["access_token"]
    org = await _org(h, owner)
    admin_email, admin = await _join(h, owner, org["id"], "admin")
    key = await h.client.post(
        f"{V1}/orgs/{org['id']}/api-keys",
        json={"name": "ci", "scopes": ["projects:read"]},
        headers=bearer(admin),
    )
    assert key.status_code == 201
    api_key = key.json()["key"]
    assert (
        await h.client.get(f"{V1}/orgs/{org['id']}/projects", headers=bearer(api_key))
    ).status_code == 200

    members = {
        m["email"]: m["user_id"]
        for m in (
            await h.client.get(f"{V1}/orgs/{org['id']}/members", headers=bearer(owner))
        ).json()
    }
    removed = await h.client.delete(
        f"{V1}/orgs/{org['id']}/members/{members[admin_email]}", headers=bearer(owner)
    )
    assert removed.status_code == 204
    assert (await h.client.get(f"{V1}/orgs/{org['id']}", headers=bearer(admin))).status_code == 404
    assert (
        await h.client.get(f"{V1}/orgs/{org['id']}/projects", headers=bearer(api_key))
    ).status_code == 401


# ---------------------------------------------------------------------------- projects
async def test_project_visibility_and_membership(h: ApiHarness) -> None:
    _, tokens = await register_and_login(h)
    owner = tokens["access_token"]
    org = await _org(h, owner)
    analyst_email, analyst = await _join(h, owner, org["id"], "analyst")
    _, viewer = await _join(h, owner, org["id"], "viewer")
    base = f"{V1}/orgs/{org['id']}/projects"
    public = (await h.client.post(base, json={"name": "Market scan"}, headers=bearer(owner))).json()
    secret = (
        await h.client.post(
            base, json={"name": "M&A target", "visibility": "restricted"}, headers=bearer(owner)
        )
    ).json()

    analyst_list = (await h.client.get(base, headers=bearer(analyst))).json()["items"]
    assert [p["id"] for p in analyst_list] == [public["id"]]
    hidden = await h.client.get(f"{base}/{secret['id']}", headers=bearer(analyst))
    assert hidden.status_code == 404  # not 403: existence is not disclosed

    members = {
        m["email"]: m["user_id"]
        for m in (
            await h.client.get(f"{V1}/orgs/{org['id']}/members", headers=bearer(owner))
        ).json()
    }
    added = await h.client.put(
        f"{base}/{secret['id']}/members/{members[analyst_email]}",
        json={"role": "viewer"},
        headers=bearer(owner),
    )
    assert added.status_code == 204
    assert (
        await h.client.get(f"{base}/{secret['id']}", headers=bearer(analyst))
    ).status_code == 200
    edit = await h.client.patch(
        f"{base}/{secret['id']}", json={"description": "x"}, headers=bearer(analyst)
    )
    assert edit.status_code == 403  # project viewer, not editor

    assert (
        await h.client.post(base, json={"name": "nope"}, headers=bearer(viewer))
    ).status_code == 403
    duplicate = await h.client.post(base, json={"name": "Market scan"}, headers=bearer(owner))
    assert duplicate.status_code == 409


async def test_non_member_cannot_be_added_to_a_project(h: ApiHarness) -> None:
    _, tokens = await register_and_login(h)
    owner = tokens["access_token"]
    org = await _org(h, owner)
    project = (
        await h.client.post(
            f"{V1}/orgs/{org['id']}/projects", json={"name": "P"}, headers=bearer(owner)
        )
    ).json()
    _, stranger_tokens = await register_and_login(h)
    stranger = stranger_tokens["access_token"]
    stranger_id = (await h.client.get(f"{V1}/auth/me", headers=bearer(stranger))).json()["id"]
    response = await h.client.put(
        f"{V1}/orgs/{org['id']}/projects/{project['id']}/members/{stranger_id}",
        json={"role": "editor"},
        headers=bearer(owner),
    )
    assert response.status_code == 404  # composite FK: must be an organisation member


async def test_project_pagination(h: ApiHarness) -> None:
    _, tokens = await register_and_login(h)
    owner = tokens["access_token"]
    org = await _org(h, owner)
    base = f"{V1}/orgs/{org['id']}/projects"
    for i in range(3):
        await h.client.post(base, json={"name": f"P{i}"}, headers=bearer(owner))
    first = (await h.client.get(f"{base}?limit=2", headers=bearer(owner))).json()
    assert len(first["items"]) == 2
    assert first["next_cursor"]
    second = (
        await h.client.get(f"{base}?limit=2&cursor={first['next_cursor']}", headers=bearer(owner))
    ).json()
    assert len(second["items"]) == 1
    assert second["next_cursor"] is None
    assert {p["name"] for p in first["items"] + second["items"]} == {"P0", "P1", "P2"}
    bad = await h.client.get(f"{base}?cursor=not-a-cursor", headers=bearer(owner))
    assert bad.status_code == 422


# ---------------------------------------------------------------------------- API keys
async def test_api_key_scopes_and_lifecycle(h: ApiHarness) -> None:
    _, tokens = await register_and_login(h)
    owner = tokens["access_token"]
    org = await _org(h, owner)
    keys = f"{V1}/orgs/{org['id']}/api-keys"
    created = await h.client.post(
        keys, json={"name": "reader", "scopes": ["projects:read"]}, headers=bearer(owner)
    )
    assert created.status_code == 201
    body = created.json()
    key = body["key"]
    assert key.startswith("argus_sk_")
    assert body["prefix"].endswith("...")
    listing = (await h.client.get(keys, headers=bearer(owner))).json()
    assert "key" not in listing[0]  # the secret is shown exactly once

    assert (
        await h.client.get(f"{V1}/orgs/{org['id']}/projects", headers=bearer(key))
    ).status_code == 200
    write = await h.client.post(
        f"{V1}/orgs/{org['id']}/projects", json={"name": "x"}, headers=bearer(key)
    )
    assert write.status_code == 403  # scope missing
    assert (
        await h.client.get(f"{V1}/auth/me", headers=bearer(key))
    ).status_code == 401  # no user session

    forbidden_scope = await h.client.post(
        keys, json={"name": "evil", "scopes": ["apikeys:manage"]}, headers=bearer(owner)
    )
    assert forbidden_scope.status_code == 422

    revoke = await h.client.delete(f"{keys}/{body['id']}", headers=bearer(owner))
    assert revoke.status_code == 204
    assert (
        await h.client.get(f"{V1}/orgs/{org['id']}/projects", headers=bearer(key))
    ).status_code == 401


@pytest.mark.parametrize(
    "token",
    ["argus_sk_short", "argus_sk_aaaaaaaaaaaa_" + "x" * 40, "argus_sk_aaaaaaaaaaaa_" + "x" * 41],
)
async def test_malformed_or_unknown_api_keys_are_rejected(h: ApiHarness, token: str) -> None:
    response = await h.client.get(f"{V1}/orgs", headers=bearer(token))
    assert response.status_code == 401


async def test_wrong_secret_for_a_real_key_id_is_rejected(h: ApiHarness) -> None:
    _, tokens = await register_and_login(h)
    org = await _org(h, tokens["access_token"])
    key = (
        await h.client.post(
            f"{V1}/orgs/{org['id']}/api-keys",
            json={"name": "k", "scopes": ["projects:read"]},
            headers=bearer(tokens["access_token"]),
        )
    ).json()["key"]
    forged = key[:-40] + ("A" * 40)
    assert (
        await h.client.get(f"{V1}/orgs/{org['id']}/projects", headers=bearer(forged))
    ).status_code == 401


async def test_key_cannot_exceed_owner_permissions_and_follows_demotion(h: ApiHarness) -> None:
    _, tokens = await register_and_login(h)
    owner = tokens["access_token"]
    org = await _org(h, owner)
    admin_email, admin = await _join(h, owner, org["id"], "admin")
    key = (
        await h.client.post(
            f"{V1}/orgs/{org['id']}/api-keys",
            json={"name": "k", "scopes": ["projects:read", "projects:create"]},
            headers=bearer(admin),
        )
    ).json()["key"]
    assert (
        await h.client.post(
            f"{V1}/orgs/{org['id']}/projects", json={"name": "k1"}, headers=bearer(key)
        )
    ).status_code == 201

    members = {
        m["email"]: m["user_id"]
        for m in (
            await h.client.get(f"{V1}/orgs/{org['id']}/members", headers=bearer(owner))
        ).json()
    }
    await h.client.patch(
        f"{V1}/orgs/{org['id']}/members/{members[admin_email]}",
        json={"role": "viewer"},
        headers=bearer(owner),
    )
    # the key's scope still says projects:create, but its owner is now a viewer
    assert (
        await h.client.post(
            f"{V1}/orgs/{org['id']}/projects", json={"name": "k2"}, headers=bearer(key)
        )
    ).status_code == 403


async def test_service_account_keys(h: ApiHarness) -> None:
    _, tokens = await register_and_login(h)
    owner = tokens["access_token"]
    org = await _org(h, owner)
    sa = (
        await h.client.post(
            f"{V1}/orgs/{org['id']}/service-accounts",
            json={"name": "etl-bot", "role": "viewer"},
            headers=bearer(owner),
        )
    ).json()
    too_much = await h.client.post(
        f"{V1}/orgs/{org['id']}/api-keys",
        json={"name": "k", "scopes": ["projects:create"], "service_account_id": sa["id"]},
        headers=bearer(owner),
    )
    assert too_much.status_code == 403  # above the service account's role
    key = (
        await h.client.post(
            f"{V1}/orgs/{org['id']}/api-keys",
            json={"name": "k", "scopes": ["projects:read"], "service_account_id": sa["id"]},
            headers=bearer(owner),
        )
    ).json()["key"]
    assert (
        await h.client.get(f"{V1}/orgs/{org['id']}/projects", headers=bearer(key))
    ).status_code == 200
    await h.client.delete(
        f"{V1}/orgs/{org['id']}/service-accounts/{sa['id']}", headers=bearer(owner)
    )
    assert (
        await h.client.get(f"{V1}/orgs/{org['id']}/projects", headers=bearer(key))
    ).status_code == 401


# ------------------------------------------------------------------- organisation policy
async def test_organisation_can_require_mfa(h: ApiHarness) -> None:
    _, tokens = await register_and_login(h)
    owner = tokens["access_token"]
    org = await _org(h, owner)
    await h.client.patch(
        f"{V1}/orgs/{org['id']}", json={"require_mfa": True}, headers=bearer(owner)
    )
    blocked = await h.client.get(f"{V1}/orgs/{org['id']}", headers=bearer(owner))
    assert blocked.status_code == 403
    assert "two-step" in blocked.json()["detail"]

    enrol = (await h.client.post(f"{V1}/auth/mfa/totp/enroll", headers=bearer(owner))).json()
    code = totp.code_at(enrol["secret"], totp.current_step(h.clock.now()))
    await h.client.post(f"{V1}/auth/mfa/totp/confirm", json={"code": code}, headers=bearer(owner))
    me = (await h.client.get(f"{V1}/auth/me", headers=bearer(owner))).json()
    h.clock.advance(30)
    challenge = (
        await h.client.post(
            f"{V1}/auth/login", json={"email": me["email"], "password": STRONG_PASSWORD}
        )
    ).json()
    code = totp.code_at(enrol["secret"], totp.current_step(h.clock.now()))
    mfa_tokens = (
        await h.client.post(
            f"{V1}/auth/mfa/verify", json={"mfa_token": challenge["mfa_token"], "code": code}
        )
    ).json()
    allowed = await h.client.get(
        f"{V1}/orgs/{org['id']}", headers=bearer(mfa_tokens["access_token"])
    )
    assert allowed.status_code == 200


async def test_org_audit_log_is_paginated_and_filtered(h: ApiHarness) -> None:
    _, tokens = await register_and_login(h)
    owner = tokens["access_token"]
    org = await _org(h, owner)
    for i in range(3):
        await h.client.post(
            f"{V1}/orgs/{org['id']}/projects", json={"name": f"A{i}"}, headers=bearer(owner)
        )
    page = (
        await h.client.get(
            f"{V1}/orgs/{org['id']}/audit-logs?limit=2&action=project.", headers=bearer(owner)
        )
    ).json()
    assert [e["action"] for e in page["items"]] == ["project.created", "project.created"]
    rest = (
        await h.client.get(
            f"{V1}/orgs/{org['id']}/audit-logs?limit=2&action=project.&cursor={page['next_cursor']}",
            headers=bearer(owner),
        )
    ).json()
    assert len(rest["items"]) == 1
    injection = await h.client.get(
        f"{V1}/orgs/{org['id']}/audit-logs?action=x%27%20OR%201=1", headers=bearer(owner)
    )
    assert injection.status_code == 422
