"""Permission catalogue and role matrix - deliberately code, not data.

A database-editable permission table is a privilege-escalation surface; this file is reviewed in
pull requests and covered by tests (the matrix in docs/security/security-model.md §2.1 is checked
against it). Custom per-organisation roles, if ever needed, would compose these permissions.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final


class Permission(StrEnum):
    ORG_READ = "org:read"
    ORG_UPDATE = "org:update"
    ORG_DELETE = "org:delete"
    ORG_EXPORT = "org:export"
    MEMBERS_READ = "members:read"
    MEMBERS_INVITE = "members:invite"
    MEMBERS_MANAGE = "members:manage"
    PROJECTS_READ = "projects:read"
    PROJECTS_CREATE = "projects:create"
    PROJECTS_UPDATE = "projects:update"
    PROJECTS_DELETE = "projects:delete"
    PROJECTS_MANAGE_MEMBERS = "projects:manage_members"
    RESEARCH_READ = "research:read"
    RESEARCH_CREATE = "research:create"
    RESEARCH_CANCEL = "research:cancel"
    DOCUMENTS_READ = "documents:read"
    DOCUMENTS_UPLOAD = "documents:upload"
    DOCUMENTS_DELETE = "documents:delete"
    DOCUMENTS_READ_RESTRICTED = "documents:read_restricted"
    SOURCES_READ = "sources:read"
    SOURCES_MANAGE = "sources:manage"
    KNOWLEDGE_READ = "knowledge:read"
    REPORTS_READ = "reports:read"
    REPORTS_EXPORT = "reports:export"
    MONITORS_READ = "monitors:read"
    MONITORS_MANAGE = "monitors:manage"
    APIKEYS_READ = "apikeys:read"
    APIKEYS_MANAGE = "apikeys:manage"
    SERVICE_ACCOUNTS_MANAGE = "service_accounts:manage"
    WEBHOOKS_MANAGE = "webhooks:manage"  # reserved: no outbound integrations exist yet
    APPROVALS_DECIDE = "approvals:decide"
    AUDIT_READ = "audit:read"
    USAGE_READ = "usage:read"
    SECURITY_MANAGE = "security:manage"


class OrgRole(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class ProjectRole(StrEnum):
    EDITOR = "editor"
    VIEWER = "viewer"


P = Permission

_VIEWER: Final = frozenset(
    {
        P.ORG_READ,
        P.MEMBERS_READ,
        P.PROJECTS_READ,
        P.RESEARCH_READ,
        P.DOCUMENTS_READ,
        P.SOURCES_READ,
        P.KNOWLEDGE_READ,
        P.REPORTS_READ,
        P.MONITORS_READ,
    }
)
_ANALYST: Final = _VIEWER | {
    P.PROJECTS_CREATE,
    P.PROJECTS_UPDATE,
    P.RESEARCH_CREATE,
    P.RESEARCH_CANCEL,
    P.DOCUMENTS_UPLOAD,
    P.DOCUMENTS_DELETE,
    P.SOURCES_MANAGE,
    P.REPORTS_EXPORT,
    P.MONITORS_MANAGE,
}
_ADMIN: Final = _ANALYST | {
    P.ORG_UPDATE,
    P.MEMBERS_INVITE,
    P.MEMBERS_MANAGE,
    P.PROJECTS_DELETE,
    P.PROJECTS_MANAGE_MEMBERS,
    P.DOCUMENTS_READ_RESTRICTED,
    P.APIKEYS_READ,
    P.APIKEYS_MANAGE,
    P.SERVICE_ACCOUNTS_MANAGE,
    P.WEBHOOKS_MANAGE,
    P.APPROVALS_DECIDE,
    P.AUDIT_READ,
    P.USAGE_READ,
    P.SECURITY_MANAGE,
}
_OWNER: Final = frozenset(Permission)

ORG_ROLE_PERMISSIONS: Final[dict[OrgRole, frozenset[Permission]]] = {
    OrgRole.OWNER: _OWNER,
    OrgRole.ADMIN: frozenset(_ADMIN),
    OrgRole.ANALYST: frozenset(_ANALYST),
    OrgRole.VIEWER: _VIEWER,
}

# Permissions that only make sense inside one project (restricted projects use project roles).
PROJECT_SCOPED: Final = frozenset(
    {
        P.PROJECTS_READ,
        P.PROJECTS_UPDATE,
        P.RESEARCH_READ,
        P.RESEARCH_CREATE,
        P.RESEARCH_CANCEL,
        P.DOCUMENTS_READ,
        P.DOCUMENTS_UPLOAD,
        P.DOCUMENTS_DELETE,
        P.SOURCES_READ,
        P.SOURCES_MANAGE,
        P.KNOWLEDGE_READ,
        P.REPORTS_READ,
        P.REPORTS_EXPORT,
        P.MONITORS_READ,
        P.MONITORS_MANAGE,
    }
)
PROJECT_ROLE_PERMISSIONS: Final[dict[ProjectRole, frozenset[Permission]]] = {
    ProjectRole.EDITOR: frozenset(_ANALYST & PROJECT_SCOPED),
    ProjectRole.VIEWER: frozenset(_VIEWER & PROJECT_SCOPED),
}

ROLE_RANK: Final = {OrgRole.VIEWER: 0, OrgRole.ANALYST: 1, OrgRole.ADMIN: 2, OrgRole.OWNER: 3}

# Scopes an API key may carry (never more than the owning principal's role at request time).
API_KEY_SCOPES: Final = frozenset(Permission) - {
    P.ORG_DELETE,
    P.ORG_EXPORT,
    P.MEMBERS_MANAGE,
    P.APIKEYS_MANAGE,
    P.SERVICE_ACCOUNTS_MANAGE,
    P.SECURITY_MANAGE,
}


def permissions_for_org_role(role: OrgRole | str) -> frozenset[Permission]:
    return ORG_ROLE_PERMISSIONS[OrgRole(role)]


def permissions_for_project_role(role: ProjectRole | str) -> frozenset[Permission]:
    return PROJECT_ROLE_PERMISSIONS[ProjectRole(role)]
