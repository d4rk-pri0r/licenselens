"""Extended Sentinel collectors: data connectors, automation rules, workspace.

Separated from ``sentinel.py`` so each module stays under the pure-LOC ceiling.
All reads are workspace-scoped ARM (no generic Azure surfaces).
"""

from __future__ import annotations

from typing import Any

from licenselens.auth import AuthContext
from licenselens.collectors.arm import (
    ArmClient,
    encode_resource_path,
    normalize_workspace_resource_id,
)
from licenselens.errors import AuthError, GraphError

DATA_CONNECTORS_API = "2023-11-01"
AUTOMATION_RULES_API = "2024-03-01"
WORKSPACE_API = "2022-10-01"

# High-value data sources a working Sentinel deployment should connect first.
KEY_CONNECTOR_KINDS: frozenset[str] = frozenset(
    {
        "AzureActiveDirectory",
        "Office365",
        "MicrosoftDefenderAdvancedThreatProtection",
        "MicrosoftThreatIntelligence",
        "MicrosoftCloudAppSecurity",
    }
)

_DEMO_WORKSPACE_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/demo-rg/providers/Microsoft.OperationalInsights/"
    "workspaces/demo-sentinel"
)


def collect_sentinel_data_connectors(
    auth: AuthContext,
    workspace_resource_id: str,
) -> list[dict[str, Any]]:
    """List SecurityInsights dataConnectors for a workspace."""
    rid = encode_resource_path(workspace_resource_id)
    path = (
        f"{rid}/providers/Microsoft.SecurityInsights/dataConnectors"
        f"?api-version={DATA_CONNECTORS_API}"
    )
    with ArmClient(auth) as client:
        return client.get_list(path, max_pages=20)


def collect_sentinel_automation_rules(
    auth: AuthContext,
    workspace_resource_id: str,
) -> list[dict[str, Any]]:
    """List SecurityInsights automationRules for a workspace."""
    rid = encode_resource_path(workspace_resource_id)
    path = (
        f"{rid}/providers/Microsoft.SecurityInsights/automationRules"
        f"?api-version={AUTOMATION_RULES_API}"
    )
    with ArmClient(auth) as client:
        return client.get_list(path, max_pages=20)


def collect_log_analytics_workspace(
    auth: AuthContext,
    workspace_resource_id: str,
) -> dict[str, Any]:
    """Read the Log Analytics workspace (retention / SKU)."""
    rid = encode_resource_path(workspace_resource_id)
    with ArmClient(auth) as client:
        return client.get(f"{rid}?api-version={WORKSPACE_API}")


def summarize_data_connectors(
    connectors: list[dict[str, Any]],
    workspace_resource_id: str,
) -> dict[str, Any]:
    kinds = sorted(
        {
            str(connector.get("kind") or "")
            for connector in connectors
            if str(connector.get("kind") or "")
        }
    )
    key = [kind for kind in kinds if kind in KEY_CONNECTOR_KINDS]
    return {
        "total_connectors": len(connectors),
        "connected_connectors": len(connectors),
        "connector_kinds": kinds,
        "key_connectors_connected": key,
        "workspace_resource_id": normalize_workspace_resource_id(workspace_resource_id),
    }


def summarize_automation_rules(
    rules: list[dict[str, Any]],
    workspace_resource_id: str,
) -> dict[str, Any]:
    playbook = 0
    enabled = 0
    for rule in rules:
        props = rule.get("properties") or {}
        if not isinstance(props, dict):
            props = {}
        for action in props.get("actions") or []:
            if isinstance(action, dict) and str(action.get("actionType") or "").lower() in {
                "runplaybook",
                "run-playbook",
            }:
                playbook += 1
        if bool(props.get("triggeringLogic")) or props.get("isEnabled"):
            enabled += 1
    return {
        "total_automation_rules": len(rules),
        "enabled_automation_rules": enabled,
        "playbook_automation_rules": playbook,
        "workspace_resource_id": normalize_workspace_resource_id(workspace_resource_id),
    }


def summarize_log_analytics_workspace(
    workspace: dict[str, Any],
    workspace_resource_id: str,
) -> dict[str, Any]:
    props = workspace.get("properties") or {}
    if not isinstance(props, dict):
        props = {}
    retention = props.get("retentionInDays")
    sku_obj = workspace.get("sku") or {}
    sku = str(sku_obj.get("name") or "") if isinstance(sku_obj, dict) else None
    return {
        "retention_in_days": int(retention) if isinstance(retention, int) else None,
        "sku": sku or None,
        "workspace_resource_id": normalize_workspace_resource_id(workspace_resource_id),
    }


def collect_sentinel_extended_bundle(
    auth: AuthContext,
    workspace_resource_id: str,
    *,
    client: ArmClient | None = None,
) -> dict[str, Any]:
    """Collect data connectors, automation rules, and workspace settings.

    Each surface fails independently so one denied permission cannot blank
    the others; per-surface errors are exposed as ``*_error`` keys.
    """
    if not workspace_resource_id or not workspace_resource_id.strip():
        raise AuthError(
            "Sentinel checks require --workspace-resource-id "
            "(or subscription/resource-group/workspace-name)."
        )
    wid = normalize_workspace_resource_id(workspace_resource_id)
    owns_client = client is None
    arm = client if client is not None else ArmClient(auth)
    bundle: dict[str, Any] = {"workspace_resource_id": wid}
    try:
        rid = encode_resource_path(wid)

        try:
            connectors = arm.get_list(
                f"{rid}/providers/Microsoft.SecurityInsights/dataConnectors"
                f"?api-version={DATA_CONNECTORS_API}",
                max_pages=20,
            )
            bundle["sentinel_data_connectors"] = summarize_data_connectors(connectors, wid)
        except GraphError as exc:
            bundle["sentinel_data_connectors_error"] = str(exc)

        try:
            rules = arm.get_list(
                f"{rid}/providers/Microsoft.SecurityInsights/automationRules"
                f"?api-version={AUTOMATION_RULES_API}",
                max_pages=20,
            )
            bundle["sentinel_automation_rules"] = summarize_automation_rules(rules, wid)
        except GraphError as exc:
            bundle["sentinel_automation_rules_error"] = str(exc)

        try:
            workspace = arm.get(f"{rid}?api-version={WORKSPACE_API}")
            bundle["sentinel_workspace"] = summarize_log_analytics_workspace(workspace, wid)
        except GraphError as exc:
            bundle["sentinel_workspace_error"] = str(exc)

        return bundle
    finally:
        if owns_client:
            arm.close()


# Dry-run: thin connectors, no automation, default retention.
DEMO_SENTINEL_DATA_CONNECTORS: dict[str, Any] = {
    "total_connectors": 1,
    "connected_connectors": 1,
    "connector_kinds": ["AzureActivity"],
    "key_connectors_connected": [],
    "workspace_resource_id": _DEMO_WORKSPACE_ID,
}

DEMO_SENTINEL_AUTOMATION_RULES: dict[str, Any] = {
    "total_automation_rules": 0,
    "enabled_automation_rules": 0,
    "playbook_automation_rules": 0,
    "workspace_resource_id": _DEMO_WORKSPACE_ID,
}

DEMO_SENTINEL_WORKSPACE: dict[str, Any] = {
    "retention_in_days": 30,
    "sku": "PerGB2018",
    "workspace_resource_id": _DEMO_WORKSPACE_ID,
}
