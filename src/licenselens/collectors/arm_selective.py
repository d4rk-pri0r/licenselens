"""Selective Azure ARM collectors (security entitlement boundary only).

No generic CSPM: only Sentinel workspace surfaces and Defender for Cloud plan
pricing that prove owned security capabilities are configured.
"""

from __future__ import annotations

from typing import Any

from licenselens.auth import AuthContext
from licenselens.cloud_endpoints import endpoints_for
from licenselens.collectors.arm import (
    ArmClient,
    encode_resource_path,
    normalize_workspace_resource_id,
)
from licenselens.collectors.contracts import (
    CloudEnvironment,
    CollectionMetadata,
    EvidenceEnvelope,
    EvidenceHealth,
    EvidenceKey,
    PaginationMetadata,
)
from licenselens.collectors.graph_collect import map_graph_error
from licenselens.errors import AuthError, GraphError
from licenselens.graph_ops import get_operation

__all__ = [
    "DEMO_ARM_SELECTIVE_BUNDLE",
    "DEMO_DEFENDER_PRICINGS",
    "SELECTIVE_ARM_OPERATIONS",
    "collect_defender_for_cloud_pricings",
    "collect_selective_arm_bundle",
    "collect_selective_arm_evidence",
    "summarize_defender_for_cloud_pricings",
]

SELECTIVE_ARM_OPERATIONS: tuple[str, ...] = (
    "arm_sentinel_alert_rules",
    "arm_sentinel_settings",
    "arm_defender_for_cloud_pricings",
)

_PRICINGS_API = "2024-01-01"
_ALERT_RULES_API = "2023-11-01"
_SETTINGS_API = "2024-03-01"


def collect_defender_for_cloud_pricings(
    client: ArmClient,
    subscription_id: str,
) -> list[dict[str, Any]]:
    """List Microsoft.Security/pricings for one subscription (plan enablement)."""
    sub = subscription_id.strip()
    path = f"subscriptions/{sub}/providers/Microsoft.Security/pricings?api-version={_PRICINGS_API}"
    return client.get_list(path, max_pages=5)


def collect_selective_arm_bundle(
    auth: AuthContext,
    *,
    workspace_resource_id: str | None = None,
    subscription_id: str | None = None,
    cloud: CloudEnvironment = CloudEnvironment.PUBLIC,
    client: ArmClient | None = None,
) -> dict[str, Any]:
    """Collect selective ARM security surfaces only."""
    _assert_cloud_supported(cloud)
    owns_client = client is None
    arm = client if client is not None else ArmClient(auth, cloud=cloud)
    try:
        bundle: dict[str, Any] = {
            "cloud": cloud.value,
            "selective_only": True,
            "sentinel_alert_rules": [],
            "sentinel_settings": [],
            "defender_for_cloud_pricings": [],
        }
        if workspace_resource_id:
            wid = encode_resource_path(workspace_resource_id)
            rules_path = (
                f"{wid}/providers/Microsoft.SecurityInsights/alertRules"
                f"?api-version={_ALERT_RULES_API}"
            )
            settings_path = (
                f"{wid}/providers/Microsoft.SecurityInsights/settings?api-version={_SETTINGS_API}"
            )
            bundle["sentinel_alert_rules"] = arm.get_list(rules_path, max_pages=40)
            bundle["sentinel_settings"] = arm.get_list(settings_path, max_pages=10)
            bundle["workspace_resource_id"] = normalize_workspace_resource_id(workspace_resource_id)
        if subscription_id:
            bundle["defender_for_cloud_pricings"] = collect_defender_for_cloud_pricings(
                arm, subscription_id
            )
            bundle["subscription_id"] = subscription_id.strip()
        return bundle
    finally:
        if owns_client:
            arm.close()


def collect_selective_arm_evidence(
    auth: AuthContext,
    *,
    workspace_resource_id: str | None = None,
    subscription_id: str | None = None,
    cloud: CloudEnvironment = CloudEnvironment.PUBLIC,
    client: ArmClient | None = None,
) -> dict[str, EvidenceEnvelope]:
    envelopes: dict[str, EvidenceEnvelope] = {}
    try:
        _assert_cloud_supported(cloud)
    except GraphError as exc:
        for op_id in SELECTIVE_ARM_OPERATIONS:
            op = get_operation(op_id)
            envelopes[op_id] = EvidenceEnvelope.unsupported(
                EvidenceKey(op.evidence_key),
                reason=str(exc),
            )
        return envelopes

    owns_client = client is None
    arm = client if client is not None else ArmClient(auth, cloud=cloud)
    try:
        if workspace_resource_id:
            envelopes["arm_sentinel_alert_rules"] = _list_envelope(
                arm,
                "arm_sentinel_alert_rules",
                (
                    f"{encode_resource_path(workspace_resource_id)}/providers/"
                    f"Microsoft.SecurityInsights/alertRules?api-version={_ALERT_RULES_API}"
                ),
            )
            envelopes["arm_sentinel_settings"] = _list_envelope(
                arm,
                "arm_sentinel_settings",
                (
                    f"{encode_resource_path(workspace_resource_id)}/providers/"
                    f"Microsoft.SecurityInsights/settings?api-version={_SETTINGS_API}"
                ),
            )
        else:
            envelopes["arm_sentinel_alert_rules"] = EvidenceEnvelope.unavailable(
                EvidenceKey("arm.sentinel_alert_rules"),
                reason="workspace_resource_id not provided",
            )
            envelopes["arm_sentinel_settings"] = EvidenceEnvelope.unavailable(
                EvidenceKey("arm.sentinel_settings"),
                reason="workspace_resource_id not provided",
            )

        if subscription_id:
            envelopes["arm_defender_for_cloud_pricings"] = _list_envelope(
                arm,
                "arm_defender_for_cloud_pricings",
                (
                    f"subscriptions/{subscription_id.strip()}/providers/"
                    f"Microsoft.Security/pricings?api-version={_PRICINGS_API}"
                ),
            )
        else:
            envelopes["arm_defender_for_cloud_pricings"] = EvidenceEnvelope.unavailable(
                EvidenceKey("arm.defender_for_cloud_pricings"),
                reason="subscription_id not provided",
            )
        return envelopes
    finally:
        if owns_client:
            arm.close()


def _list_envelope(client: ArmClient, operation_id: str, path: str) -> EvidenceEnvelope:
    op = get_operation(operation_id)
    key = EvidenceKey(op.evidence_key)
    try:
        items = client.get_list(path, max_pages=op.max_pages)
    except AuthError as exc:
        return EvidenceEnvelope.denied(key, reason=str(exc))
    except GraphError as exc:
        return map_graph_error(key, exc, source=operation_id)
    return EvidenceEnvelope(
        key=key,
        health=EvidenceHealth.OK,
        value=items,
        metadata=CollectionMetadata(
            source=operation_id,
            items_collected=len(items),
            pagination=PaginationMetadata(pages_read=1, max_pages=op.max_pages),
        ),
    )


def summarize_defender_for_cloud_pricings(
    pricings: list[dict[str, Any]],
    subscription_id: str,
) -> dict[str, Any]:
    """Interpret Defender for Cloud plan pricing tiers (Standard vs Free)."""
    standard: list[str] = []
    free: list[str] = []
    for pricing in pricings:
        name = str(pricing.get("name") or "")
        if not name:
            continue
        props = pricing.get("properties") or {}
        tier = ""
        if isinstance(props, dict):
            tier = str(props.get("pricingTier") or "").lower()
        if tier == "standard":
            standard.append(name)
        else:
            free.append(name)
    return {
        "standard_plans": sorted(standard),
        "free_plans": sorted(free),
        "total_plans": len(standard) + len(free),
        "subscription_id": subscription_id.strip(),
    }


def _assert_cloud_supported(cloud: CloudEnvironment) -> None:
    endpoints = endpoints_for(cloud)
    if cloud is CloudEnvironment.CHINA:
        raise GraphError(
            f"selective ARM security collectors do not support cloud {cloud.value}",
            status_code=400,
        )
    _ = endpoints


DEMO_ARM_SELECTIVE_BUNDLE: dict[str, Any] = {
    "cloud": "public",
    "selective_only": True,
    "workspace_resource_id": (
        "/subscriptions/00000000-0000-0000-0000-000000000000/"
        "resourceGroups/demo-rg/providers/Microsoft.OperationalInsights/"
        "workspaces/demo-sentinel"
    ),
    "subscription_id": "00000000-0000-0000-0000-000000000000",
    "sentinel_alert_rules": [{"name": "demo-rule", "kind": "Scheduled"}],
    "sentinel_settings": [{"name": "EntityAnalytics", "kind": "EntityAnalytics"}],
    "defender_for_cloud_pricings": [
        {
            "name": "VirtualMachines",
            "properties": {"pricingTier": "Standard"},
        }
    ],
}

DEMO_DEFENDER_PRICINGS: dict[str, Any] = {
    "standard_plans": ["VirtualMachines"],
    "free_plans": [],
    "total_plans": 1,
    "subscription_id": "00000000-0000-0000-0000-000000000000",
}
