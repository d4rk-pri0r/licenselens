"""Collect Conditional Access policies from Microsoft Graph."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.privileged_roles import PRIVILEGED_ROLE_TEMPLATE_IDS
from licenselens.graph import GraphClient

LEGACY_CLIENT_APP_TYPES: frozenset[str] = frozenset({"exchangeActiveSync", "other"})


def collect_ca_policies(client: GraphClient) -> list[dict[str, Any]]:
    """GET /identity/conditionalAccess/policies (all pages)."""
    return client.get_list("/identity/conditionalAccess/policies")


def policy_state(policy: dict[str, Any]) -> str:
    return str(policy.get("state") or "disabled").lower()


def is_enabled(policy: dict[str, Any]) -> bool:
    return policy_state(policy) == "enabled"


def is_report_only(policy: dict[str, Any]) -> bool:
    return policy_state(policy) == "enabledforreportingbutnotenforced"


def _grant_controls(policy: dict[str, Any]) -> list[str]:
    grants = policy.get("grantControls") or {}
    built_in = grants.get("builtInControls") or []
    return [str(c).lower() for c in built_in]


def requires_mfa(policy: dict[str, Any]) -> bool:
    controls = set(_grant_controls(policy))
    return bool(controls & {"mfa", "phishingresistantmfa", "strengthauthentication"})


def is_block_policy(policy: dict[str, Any]) -> bool:
    return "block" in _grant_controls(policy)


def _conditions(policy: dict[str, Any]) -> dict[str, Any]:
    cond = policy.get("conditions") or {}
    return cond if isinstance(cond, dict) else {}


def includes_all_users(policy: dict[str, Any]) -> bool:
    users = _conditions(policy).get("users") or {}
    include_users = [str(u) for u in (users.get("includeUsers") or [])]
    return any(u.lower() == "all" for u in include_users)


def included_roles(policy: dict[str, Any]) -> set[str]:
    users = _conditions(policy).get("users") or {}
    return {str(r).lower() for r in (users.get("includeRoles") or [])}


def targets_privileged_roles(policy: dict[str, Any]) -> bool:
    roles = included_roles(policy)
    if not roles:
        return False
    privileged = {r.lower() for r in PRIVILEGED_ROLE_TEMPLATE_IDS}
    return bool(roles & privileged)


def client_app_types(policy: dict[str, Any]) -> set[str]:
    apps = _conditions(policy).get("clientAppTypes") or []
    return {str(a) for a in apps}


def is_legacy_auth_block(policy: dict[str, Any]) -> bool:
    """Heuristic: enabled/report-only block policy scoped to legacy client apps."""
    if not (is_enabled(policy) or is_report_only(policy)):
        return False
    if not is_block_policy(policy):
        return False
    apps = client_app_types(policy)
    if not apps:
        return False
    # Common pattern: only legacy types, or legacy types explicitly listed
    legacy_hit = bool(apps & LEGACY_CLIENT_APP_TYPES)
    modern = apps - LEGACY_CLIENT_APP_TYPES - {"all"}
    if legacy_hit and not modern:
        return True
    # Some tenants set clientAppTypes to exchangeActiveSync + other only
    return legacy_hit and apps <= (LEGACY_CLIENT_APP_TYPES | {"all"})


def sign_in_risk_levels(policy: dict[str, Any]) -> list[str]:
    levels = _conditions(policy).get("signInRiskLevels") or []
    return [str(x) for x in levels]


def user_risk_levels(policy: dict[str, Any]) -> list[str]:
    levels = _conditions(policy).get("userRiskLevels") or []
    return [str(x) for x in levels]


def has_risk_conditions(policy: dict[str, Any]) -> bool:
    return bool(sign_in_risk_levels(policy) or user_risk_levels(policy))


# --- Dry-run demo policies (mid-maturity tenant) ---

DEMO_CA_POLICIES: list[dict[str, Any]] = [
    {
        "id": "demo-mfa-all",
        "displayName": "Demo: MFA for all users",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"], "includeRoles": []},
            "clientAppTypes": ["all"],
            "signInRiskLevels": [],
            "userRiskLevels": [],
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"],
        },
    },
    {
        "id": "demo-legacy-report",
        "displayName": "Demo: Block legacy auth (report-only)",
        "state": "enabledForReportingButNotEnforced",
        "conditions": {
            "users": {"includeUsers": ["All"], "includeRoles": []},
            "clientAppTypes": ["exchangeActiveSync", "other"],
            "signInRiskLevels": [],
            "userRiskLevels": [],
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"],
        },
    },
    # No risk-based CA in demo → Identity Protection check should GAP
]
