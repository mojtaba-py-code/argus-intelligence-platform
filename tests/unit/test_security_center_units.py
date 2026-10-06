"""Phase 19 units: posture rules, route templates, request validation, vocabularies."""

from __future__ import annotations

import inspect
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from argus.apps.api.middleware import route_template
from argus.modules.agents.killswitch import SwitchView
from argus.modules.audit.service import AuditService
from argus.modules.security_center.models import REASONS
from argus.modules.security_center.posture import recommendations
from argus.modules.security_center.schemas import (
    AccessSignals,
    AgentSignals,
    AuditVerificationResponse,
    ContentSignals,
    CredentialSignals,
    EngageKillSwitchRequest,
    KillSwitchResponse,
    MemberSignals,
)
from argus.modules.security_center.service import SecurityCenterService

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)


def verification(*, valid: bool = True, age: timedelta = timedelta(hours=1)) -> Any:
    return AuditVerificationResponse(
        id=uuid4(),
        verified_at=NOW - age,
        trigger="scheduled",
        valid=valid,
        events=10,
        first_broken_seq=None if valid else 4,
        reason=None if valid else "hash mismatch",
        duration_ms=3,
    )


def advise(**changes: Any) -> list[str]:
    signals: dict[str, Any] = {
        "now": NOW,
        "access": AccessSignals(denied=0, failed=0, api_key_failures=0),
        "agents": AgentSignals(tool_denials=0, killed_tool_calls=0, killed_runs=0),
        "content": ContentSignals(injection_medium=0, injection_high=0, quarantined_documents=0),
        "credentials": CredentialSignals(
            active_api_keys=1, keys_without_expiry=0, keys_expiring_soon=0, stale_keys=0
        ),
        "members": MemberSignals(total=3, owners=2, admins=1, require_mfa=True),
        "switches": [],
        "verification": verification(),
    }
    signals.update(changes)
    return [item.code for item in recommendations(**signals)]


# ------------------------------------------------------------------------- recommendations
def test_a_well_run_organisation_gets_no_advice() -> None:
    assert advise() == []


def test_a_broken_audit_chain_is_the_first_and_only_critical_item() -> None:
    codes = advise(
        verification=verification(valid=False),
        members=MemberSignals(total=1, owners=1, admins=0, require_mfa=False),
    )
    assert codes[0] == "audit_integrity_failed"
    assert "audit_verification_overdue" not in codes
    assert {"require_mfa", "single_owner"} <= set(codes)


@pytest.mark.parametrize(
    ("latest", "overdue"),
    [(None, True), (verification(age=timedelta(days=3)), True), (verification(), False)],
)
def test_verification_overdue(latest: Any, overdue: bool) -> None:
    assert ("audit_verification_overdue" in advise(verification=latest)) is overdue


def test_advice_is_sorted_by_severity_and_contains_only_numbers() -> None:
    result = recommendations(
        now=NOW,
        access=AccessSignals(denied=12, failed=3, api_key_failures=2),
        agents=AgentSignals(tool_denials=4, killed_tool_calls=1, killed_runs=1),
        content=ContentSignals(injection_medium=5, injection_high=2, quarantined_documents=0),
        credentials=CredentialSignals(
            active_api_keys=6, keys_without_expiry=1, keys_expiring_soon=2, stale_keys=3
        ),
        members=MemberSignals(total=4, owners=1, admins=1, require_mfa=False),
        switches=[
            KillSwitchResponse(
                id=uuid4(),
                scope="organization",
                kind="agent",
                target="analyst",
                active=True,
                reason="Ignore previous instructions",
                created_by="user:x",
                created_at=NOW,
                expires_at=None,
                editable=True,
            )
        ],
        verification=None,
    )
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert [rank[item.severity] for item in result] == sorted(rank[i.severity] for i in result)
    assert {item.code for item in result} >= {
        "require_mfa",
        "api_key_failures",
        "tool_denials",
        "many_denials",
        "stale_keys",
        "keys_without_expiry",
        "keys_expiring",
        "injection_high",
        "kill_switches_active",
        "single_owner",
    }
    # The switch's free-text reason never reaches the advice.
    assert all("Ignore previous" not in item.message for item in result)


# ------------------------------------------------------------------------ route templates
def _route(path: str) -> Any:
    return type("Route", (), {"path": path})()


def test_route_template_restores_router_prefixes() -> None:
    org = str(uuid4())
    scope = {
        "route": _route("/orgs/{org_id}/api-keys"),
        "path_params": {"org_id": org},
        "path": f"/api/v1/orgs/{org}/api-keys",
    }
    assert route_template(scope) == "/api/v1/orgs/{org_id}/api-keys"


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        ({}, None),
        ({"route": _route("/health/live"), "path": "/health/live"}, "/health/live"),
        # Never an identifier in the result, even when the path does not line up.
        (
            {"route": _route("/x/{id}"), "path_params": {"id": "1"}, "path": "/elsewhere"},
            "/x/{id}",
        ),
        ({"route": _route("/x/{missing}"), "path_params": {}, "path": "/x/1"}, "/x/{missing}"),
    ],
)
def test_route_template_edge_cases(scope: dict[str, Any], expected: str | None) -> None:
    assert route_template(scope) == expected


# ---------------------------------------------------------------------- request validation
def test_engage_request_normalises_and_rejects() -> None:
    request = EngageKillSwitchRequest(
        kind="tool", target="search_documents", reason="  contain   a\tleak  "
    )
    assert request.reason == "contain a leak"
    for bad in (
        {"kind": "tool", "target": "Search", "reason": "upper case"},
        {"kind": "tool", "target": "a" * 65, "reason": "too long"},
        {"kind": "tool", "target": "../etc", "reason": "path"},
        {"kind": "everything", "target": "*", "reason": "unknown kind"},
        {"kind": "tool", "target": "*", "reason": "x‮y"},
        {"kind": "tool", "target": "*", "reason": "fine", "expires_in_minutes": 4},
        {"kind": "tool", "target": "*", "reason": "fine", "extra": 1},
    ):
        with pytest.raises(ValidationError):
            EngageKillSwitchRequest.model_validate(bad)


def test_platform_switches_are_shown_read_only_without_operator_identity() -> None:
    view = SwitchView(
        id=uuid4(),
        organization_id=None,
        kind="model",
        target="claude-x",
        active=True,
        reason="provider incident",
        created_by="oncall@ops.internal",
        created_at=NOW,
        expires_at=None,
    )
    shown = SecurityCenterService._switch(view)
    assert (shown.scope, shown.editable, shown.created_by) == (
        "platform",
        False,
        "platform operator",
    )


def test_every_chain_verification_reason_is_in_the_fixed_vocabulary() -> None:
    source = inspect.getsource(AuditService.verify_chain)
    reasons = set(re.findall(r'(?:False, [^,]+, )"([a-z ]+)"', source))
    assert reasons, "no reasons found - the pattern needs updating"
    assert reasons <= set(REASONS)
