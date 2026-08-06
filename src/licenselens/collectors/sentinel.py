"""Collect Microsoft Sentinel analytics rules and UEBA settings via ARM."""

from __future__ import annotations

from typing import Any

from licenselens.auth import AuthContext
from licenselens.collectors.arm import (
    ArmClient,
    encode_resource_path,
    normalize_workspace_resource_id,
)
from licenselens.errors import AuthError, GraphError

ALERT_RULES_API = "2023-11-01"
SETTINGS_API = "2024-03-01"


def collect_sentinel_alert_rules(
    auth: AuthContext,
    workspace_resource_id: str,
) -> list[dict[str, Any]]:
    """List SecurityInsights alertRules for a workspace."""
    rid = encode_resource_path(workspace_resource_id)
    path = (
        f"{rid}/providers/Microsoft.SecurityInsights/alertRules"
        f"?api-version={ALERT_RULES_API}"
    )
    with ArmClient(auth) as client:
        return client.get_list(path, max_pages=40)


def collect_sentinel_settings(
    auth: AuthContext,
    workspace_resource_id: str,
) -> list[dict[str, Any]]:
    """List SecurityInsights settings (includes EntityAnalytics / UEBA)."""
    rid = encode_resource_path(workspace_resource_id)
    path = (
        f"{rid}/providers/Microsoft.SecurityInsights/settings"
        f"?api-version={SETTINGS_API}"
    )
    with ArmClient(auth) as client:
        return client.get_list(path, max_pages=10)


def summarize_alert_rules(rules: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rules)
    enabled_scheduled = 0
    enabled_any = 0
    tactics: set[str] = set()
    sample_enabled: list[str] = []

    for rule in rules:
        kind = str(rule.get("kind") or "")
        props = rule.get("properties") or {}
        if not isinstance(props, dict):
            props = {}
        enabled = bool(props.get("enabled"))
        if enabled:
            enabled_any += 1
            name = str(props.get("displayName") or rule.get("name") or "unnamed")
            if len(sample_enabled) < 12:
                sample_enabled.append(name)
            for t in props.get("tactics") or []:
                tactics.add(str(t))
            if kind.lower() in {"scheduled", "nrt"}:
                enabled_scheduled += 1

    return {
        "total_rules": total,
        "enabled_rules": enabled_any,
        "enabled_scheduled_or_nrt": enabled_scheduled,
        "tactics": sorted(tactics),
        "tactic_count": len(tactics),
        "sample_enabled_rules": sample_enabled,
        "workspace_resource_id": None,
    }


def summarize_ueba(settings: list[dict[str, Any]]) -> dict[str, Any]:
    """Interpret UEBA / Entity Analytics enablement from settings list."""
    entity = None
    ueba = None
    names = []
    for item in settings:
        name = str(item.get("name") or item.get("kind") or "").lower()
        names.append(name)
        props = item.get("properties") or {}
        if not isinstance(props, dict):
            props = {}
        # Common shapes across API versions
        if "entityanalytics" in name or str(item.get("kind") or "").lower() == "entityanalytics":
            entity = item
        if "ueba" in name or "entitybehavior" in name:
            ueba = item

    def _is_on(doc: dict[str, Any] | None) -> bool | None:
        if not doc:
            return None
        props = doc.get("properties") or {}
        if not isinstance(props, dict):
            return None
        for key in (
            "isEnabled",
            "enabled",
            "enableEntityAnalytics",
            "isEntityAnalyticsEnabled",
        ):
            if key in props:
                return bool(props.get(key))
        # Some payloads nest status
        status = props.get("status") or props.get("provisioningState")
        if isinstance(status, str) and status.lower() in {"enabled", "succeeded", "active"}:
            return True
        if isinstance(status, str) and status.lower() in {"disabled", "none"}:
            return False
        return None

    entity_on = _is_on(entity)
    ueba_on = _is_on(ueba)
    enabled = False
    if entity_on is True or ueba_on is True:
        enabled = True
    elif entity_on is False and ueba_on is False:
        enabled = False
    elif entity_on is False and ueba_on is None:
        enabled = False
    elif entity is None and ueba is None:
        enabled = False

    return {
        "ueba_enabled": enabled,
        "entity_analytics_enabled": entity_on,
        "ueba_setting_enabled": ueba_on,
        "setting_names": names,
        "raw_entity_present": entity is not None,
        "raw_ueba_present": ueba is not None,
    }


def collect_sentinel_bundle(
    auth: AuthContext,
    workspace_resource_id: str,
) -> dict[str, Any]:
    """Fetch rules + settings and return evaluator-ready summary."""
    if not workspace_resource_id or not workspace_resource_id.strip():
        raise AuthError(
            "Sentinel checks require --workspace-resource-id "
            "(or subscription/resource-group/workspace-name)."
        )
    wid = normalize_workspace_resource_id(workspace_resource_id)
    try:
        rules = collect_sentinel_alert_rules(auth, wid)
    except GraphError:
        raise
    try:
        settings = collect_sentinel_settings(auth, wid)
    except GraphError as exc:
        # Settings may fail independently
        settings = []
        settings_error = str(exc)
    else:
        settings_error = None

    rule_summary = summarize_alert_rules(rules)
    rule_summary["workspace_resource_id"] = wid
    ueba_summary = summarize_ueba(settings)
    ueba_summary["workspace_resource_id"] = wid
    if settings_error:
        ueba_summary["settings_error"] = settings_error
    return {
        "sentinel_rules": rule_summary,
        "sentinel_ueba": ueba_summary,
        "workspace_resource_id": wid,
    }


# Dry-run: thin rule set, UEBA off
DEMO_SENTINEL_RULES: dict[str, Any] = {
    "total_rules": 3,
    "enabled_rules": 2,
    "enabled_scheduled_or_nrt": 2,
    "tactics": ["InitialAccess", "Persistence"],
    "tactic_count": 2,
    "sample_enabled_rules": ["Demo Sign-in spike", "Demo Rare process"],
    "workspace_resource_id": (
        "/subscriptions/00000000-0000-0000-0000-000000000000/"
        "resourceGroups/demo-rg/providers/Microsoft.OperationalInsights/"
        "workspaces/demo-sentinel"
    ),
}

DEMO_SENTINEL_UEBA: dict[str, Any] = {
    "ueba_enabled": False,
    "entity_analytics_enabled": False,
    "ueba_setting_enabled": None,
    "setting_names": [],
    "raw_entity_present": False,
    "raw_ueba_present": False,
    "workspace_resource_id": DEMO_SENTINEL_RULES["workspace_resource_id"],
}
