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


# Built-in authentication strength template IDs (Microsoft Graph).
PHISHING_RESISTANT_STRENGTH_IDS: frozenset[str] = frozenset(
    {
        "00000000-0000-0000-0000-000000000003",  # Phishing-resistant MFA
    }
)
PASSWORDLESS_STRENGTH_IDS: frozenset[str] = frozenset(
    {
        "00000000-0000-0000-0000-000000000004",  # Passwordless MFA
    }
)


def requires_mfa(policy: dict[str, Any]) -> bool:
    controls = set(_grant_controls(policy))
    if controls & {"mfa", "phishingresistantmfa", "strengthauthentication"}:
        return True
    return bool(authentication_strength_id(policy))


def is_block_policy(policy: dict[str, Any]) -> bool:
    return "block" in _grant_controls(policy)


def _conditions(policy: dict[str, Any]) -> dict[str, Any]:
    cond = policy.get("conditions") or {}
    return cond if isinstance(cond, dict) else {}


def _users(policy: dict[str, Any]) -> dict[str, Any]:
    users = _conditions(policy).get("users") or {}
    return users if isinstance(users, dict) else {}


def includes_all_users(policy: dict[str, Any]) -> bool:
    include_users = [str(u) for u in (_users(policy).get("includeUsers") or [])]
    return any(u.lower() == "all" for u in include_users)


def included_roles(policy: dict[str, Any]) -> set[str]:
    return {str(r).lower() for r in (_users(policy).get("includeRoles") or [])}


def excluded_principals(policy: dict[str, Any]) -> set[str]:
    users = _users(policy)
    out: set[str] = set()
    for key in ("excludeUsers", "excludeGroups", "excludeRoles"):
        out.update(str(item).lower() for item in (users.get(key) or []) if item)
    return out


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
    legacy_hit = bool(apps & LEGACY_CLIENT_APP_TYPES)
    modern = apps - LEGACY_CLIENT_APP_TYPES - {"all"}
    if legacy_hit and not modern:
        return True
    return legacy_hit and apps <= (LEGACY_CLIENT_APP_TYPES | {"all"})


def sign_in_risk_levels(policy: dict[str, Any]) -> list[str]:
    levels = _conditions(policy).get("signInRiskLevels") or []
    return [str(x).lower() for x in levels]


def user_risk_levels(policy: dict[str, Any]) -> list[str]:
    levels = _conditions(policy).get("userRiskLevels") or []
    return [str(x).lower() for x in levels]


def has_risk_conditions(policy: dict[str, Any]) -> bool:
    return bool(sign_in_risk_levels(policy) or user_risk_levels(policy))


def authentication_strength_id(policy: dict[str, Any]) -> str | None:
    grants = policy.get("grantControls") or {}
    if not isinstance(grants, dict):
        return None
    strength = grants.get("authenticationStrength") or {}
    if not isinstance(strength, dict):
        return None
    strength_id = strength.get("id")
    return str(strength_id).lower() if strength_id else None


def requires_phishing_resistant(policy: dict[str, Any]) -> bool:
    controls = set(_grant_controls(policy))
    if "phishingresistantmfa" in controls:
        return True
    strength = authentication_strength_id(policy)
    if strength and strength in PHISHING_RESISTANT_STRENGTH_IDS:
        return True
    grants = policy.get("grantControls") or {}
    if isinstance(grants, dict):
        strength_obj = grants.get("authenticationStrength") or {}
        if isinstance(strength_obj, dict):
            name = str(strength_obj.get("displayName") or "").lower()
            if "phishing" in name:
                return True
    return False


def requires_managed_device(policy: dict[str, Any]) -> bool:
    controls = set(_grant_controls(policy))
    return bool(controls & {"compliantdevice", "domainjoineddevice"})


def targets_register_security_info(policy: dict[str, Any]) -> bool:
    apps = _conditions(policy).get("applications") or {}
    if not isinstance(apps, dict):
        return False
    actions = {str(a).lower() for a in (apps.get("includeUserActions") or [])}
    return "urn:user:registersecurityinfo" in actions


def is_device_code_block(policy: dict[str, Any]) -> bool:
    if not is_block_policy(policy):
        return False
    flows = _conditions(policy).get("authenticationFlows") or {}
    if not isinstance(flows, dict):
        return False
    transfer = flows.get("transferMethods")
    if transfer is None:
        return False
    text = str(transfer).lower()
    return "devicecode" in text.replace(" ", "").replace("_", "")


def blocks_high_user_risk(policy: dict[str, Any]) -> bool:
    return is_block_policy(policy) and "high" in user_risk_levels(policy)


def blocks_high_sign_in_risk(policy: dict[str, Any]) -> bool:
    return is_block_policy(policy) and "high" in sign_in_risk_levels(policy)


def includes_all_cloud_apps(policy: dict[str, Any]) -> bool:
    apps = _conditions(policy).get("applications") or {}
    if not isinstance(apps, dict):
        return False
    include = [str(a).lower() for a in (apps.get("includeApplications") or [])]
    return "all" in include


def unjustified_exclusions(
    policy: dict[str, Any],
    justified_principal_ids: set[str],
) -> list[str]:
    justified = {j.lower() for j in justified_principal_ids}
    excluded = excluded_principals(policy)
    return sorted(excluded - justified)


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
        "id": "demo-risk-signin",
        "displayName": "Demo: Require MFA for sign-in risk",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"], "includeRoles": []},
            "clientAppTypes": ["all"],
            "signInRiskLevels": ["high", "medium"],
            "userRiskLevels": [],
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"],
        },
    },
    {
        "id": "demo-risk-user",
        "displayName": "Demo: Require password change for user risk",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"], "includeRoles": []},
            "clientAppTypes": ["all"],
            "signInRiskLevels": [],
            "userRiskLevels": ["high"],
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["passwordChange"],
        },
    },
]
