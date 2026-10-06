"""Security posture: counting signals from stored data and turning them into advice.

Every number comes from rows the platform already keeps (audit log, tool calls, agent runs,
snapshots, documents, sources, model ledger, API keys, memberships), read inside the tenant's
own row-level-security context. The recommendations are deterministic rules - no model is
involved in judging an organisation's security.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Final
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from argus.modules.security_center.schemas import (
    AccessSignals,
    AgentSignals,
    AuditVerificationResponse,
    ContentSignals,
    CredentialSignals,
    EgressSignals,
    KillSwitchResponse,
    MemberSignals,
    ModelSignals,
    Recommendation,
)

EXPIRY_WARNING: Final = timedelta(days=14)
STALE_AFTER: Final = timedelta(days=90)
VERIFICATION_OVERDUE: Final = timedelta(hours=48)
_SEVERITY_ORDER: Final = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# One statement per signal group, each bounded by the organisation and the time window. The
# explicit organisation filter repeats what row-level security already enforces (defence in
# depth, and it lets the planner use the (organization_id, time) indexes).
_ACCESS = text(
    "SELECT count(*) FILTER (WHERE outcome = 'denied') AS denied,"
    " count(*) FILTER (WHERE outcome = 'failure') AS failed,"
    " count(*) FILTER (WHERE action = 'api_key.authentication_failed') AS api_key_failures"
    " FROM audit_logs WHERE organization_id = :org AND occurred_at >= :since"
)
_TOOLS = text(
    "SELECT count(*) FILTER (WHERE outcome = 'denied') AS denied,"
    " count(*) FILTER (WHERE outcome = 'killed') AS killed"
    " FROM tool_calls WHERE organization_id = :org AND created_at >= :since"
)
_KILLED_RUNS = text(
    "SELECT count(*) FROM agent_runs"
    " WHERE organization_id = :org AND status = 'killed' AND created_at >= :since"
)
_INJECTION = text(
    "SELECT level, count(*) AS n FROM ("
    " SELECT injection_level AS level FROM source_snapshots"
    "  WHERE organization_id = :org AND fetched_at >= :since"
    "  AND injection_level IN ('medium', 'high')"
    " UNION ALL"
    " SELECT injection_level FROM documents"
    "  WHERE organization_id = :org AND created_at >= :since"
    "  AND injection_level IN ('medium', 'high')"
    ") flagged GROUP BY level"
)
_QUARANTINED = text(
    "SELECT count(*) FROM documents"
    " WHERE organization_id = :org AND status = 'quarantined' AND updated_at >= :since"
)
_EGRESS = text(
    "SELECT coalesce(last_error_code, 'blocked') AS reason, count(*) AS n FROM sources"
    " WHERE organization_id = :org AND status = 'blocked' AND updated_at >= :since"
    " GROUP BY 1"
)
_MODELS = text(
    "SELECT count(*) FILTER (WHERE outcome = 'blocked_policy') AS policy,"
    " count(*) FILTER (WHERE outcome = 'blocked_budget') AS budget,"
    " count(*) FILTER (WHERE outcome = 'refused') AS refused"
    " FROM llm_requests WHERE organization_id = :org AND created_at >= :since"
)
_KEYS = text(
    "SELECT count(*) AS active,"
    " count(*) FILTER (WHERE expires_at IS NULL) AS without_expiry,"
    " count(*) FILTER (WHERE expires_at <= :soon) AS expiring,"
    " count(*) FILTER (WHERE coalesce(last_used_at, created_at) < :stale) AS stale"
    " FROM api_keys WHERE organization_id = :org AND revoked_at IS NULL"
    " AND (expires_at IS NULL OR expires_at > :now)"
)
_MEMBERS = text(
    "SELECT role, count(*) AS n FROM organization_members WHERE organization_id = :org GROUP BY role"
)


async def access_signals(session: AsyncSession, org: UUID, since: datetime) -> AccessSignals:
    row = (await session.execute(_ACCESS, {"org": org, "since": since})).one()
    return AccessSignals(
        denied=row.denied, failed=row.failed, api_key_failures=row.api_key_failures
    )


async def agent_signals(session: AsyncSession, org: UUID, since: datetime) -> AgentSignals:
    params = {"org": org, "since": since}
    tools = (await session.execute(_TOOLS, params)).one()
    killed_runs = (await session.execute(_KILLED_RUNS, params)).scalar_one()
    return AgentSignals(
        tool_denials=tools.denied, killed_tool_calls=tools.killed, killed_runs=killed_runs
    )


async def content_signals(session: AsyncSession, org: UUID, since: datetime) -> ContentSignals:
    params = {"org": org, "since": since}
    levels = {row.level: row.n for row in await session.execute(_INJECTION, params)}
    quarantined = (await session.execute(_QUARANTINED, params)).scalar_one()
    return ContentSignals(
        injection_medium=levels.get("medium", 0),
        injection_high=levels.get("high", 0),
        quarantined_documents=quarantined,
    )


async def egress_signals(session: AsyncSession, org: UUID, since: datetime) -> EgressSignals:
    reasons = {
        row.reason: row.n for row in await session.execute(_EGRESS, {"org": org, "since": since})
    }
    return EgressSignals(blocked=sum(reasons.values()), by_reason=dict(sorted(reasons.items())))


async def model_signals(session: AsyncSession, org: UUID, since: datetime) -> ModelSignals:
    row = (await session.execute(_MODELS, {"org": org, "since": since})).one()
    return ModelSignals(policy_blocks=row.policy, budget_blocks=row.budget, refusals=row.refused)


async def credential_signals(session: AsyncSession, org: UUID, now: datetime) -> CredentialSignals:
    row = (
        await session.execute(
            _KEYS,
            {"org": org, "now": now, "soon": now + EXPIRY_WARNING, "stale": now - STALE_AFTER},
        )
    ).one()
    return CredentialSignals(
        active_api_keys=row.active,
        keys_without_expiry=row.without_expiry,
        keys_expiring_soon=row.expiring,
        stale_keys=row.stale,
    )


async def member_signals(session: AsyncSession, org: UUID, *, require_mfa: bool) -> MemberSignals:
    roles = {row.role: row.n for row in await session.execute(_MEMBERS, {"org": org})}
    return MemberSignals(
        total=sum(roles.values()),
        owners=roles.get("owner", 0),
        admins=roles.get("admin", 0),
        require_mfa=require_mfa,
    )


def recommendations(
    *,
    now: datetime,
    access: AccessSignals,
    agents: AgentSignals,
    content: ContentSignals,
    credentials: CredentialSignals,
    members: MemberSignals,
    switches: list[KillSwitchResponse],
    verification: AuditVerificationResponse | None,
) -> list[Recommendation]:
    """Plain rules over the signals, most severe first. Messages contain only numbers and fixed
    words - never stored text - so the dashboard cannot be used to display injected content."""
    advice: list[Recommendation] = []

    def add(code: str, severity: str, message: str) -> None:
        advice.append(
            Recommendation.model_validate({"code": code, "severity": severity, "message": message})
        )

    if verification is not None and not verification.valid:
        add(
            "audit_integrity_failed",
            "critical",
            f"The audit log failed its integrity check at event {verification.first_broken_seq}."
            " Treat this as a security incident and keep the database unchanged for investigation.",
        )
    elif verification is None or now - verification.verified_at > VERIFICATION_OVERDUE:
        add(
            "audit_verification_overdue",
            "medium",
            "The audit log has not been verified in the last 48 hours. Check that the scheduler"
            " is running, or start a verification now.",
        )
    if not members.require_mfa:
        add(
            "require_mfa",
            "high",
            "Two-step verification is optional. Require it for every member in the"
            " organisation settings.",
        )
    if members.owners == 1:
        add(
            "single_owner",
            "medium",
            "The organisation has one owner. Add a second owner so losing one account does not"
            " lock everyone out.",
        )
    if credentials.keys_without_expiry:
        add(
            "keys_without_expiry",
            "medium",
            f"{credentials.keys_without_expiry} active API key(s) never expire. Give every key an"
            " expiry date and rotate it.",
        )
    if credentials.keys_expiring_soon:
        add(
            "keys_expiring",
            "low",
            f"{credentials.keys_expiring_soon} API key(s) expire within 14 days. Rotate them"
            " before integrations stop working.",
        )
    if credentials.stale_keys:
        add(
            "stale_keys",
            "medium",
            f"{credentials.stale_keys} API key(s) have not been used for 90 days. Revoke keys"
            " nobody uses.",
        )
    if access.api_key_failures:
        add(
            "api_key_failures",
            "high",
            f"{access.api_key_failures} request(s) used an invalid or revoked API key. Find the"
            " client and check whether a key has leaked.",
        )
    if access.denied >= 10:
        add(
            "many_denials",
            "medium",
            f"{access.denied} actions were refused to members. Review the security events for"
            " probing or roles that are too narrow.",
        )
    if agents.tool_denials:
        add(
            "tool_denials",
            "high",
            f"Agents requested {agents.tool_denials} tool call(s) they were not allowed to make."
            " Review the agent runs: refused tool calls often follow injected instructions.",
        )
    if content.injection_high:
        add(
            "injection_high",
            "low",
            f"{content.injection_high} page(s) or document(s) carried likely prompt-injection"
            " text. They were kept out of every model context; review their sources.",
        )
    org_switches = [s for s in switches if s.scope == "organization" and s.active]
    if org_switches:
        add(
            "kill_switches_active",
            "low",
            f"{len(org_switches)} kill switch(es) are engaged for this organisation. Release"
            " them when the incident is over.",
        )
    advice.sort(key=lambda item: _SEVERITY_ORDER[item.severity])
    return advice
