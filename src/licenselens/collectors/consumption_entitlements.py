"""Consumption entitlement observation (WS2-A).

Four catalog capabilities are consumption-metered in Azure rather than
SKU-unlocked from Microsoft Graph ``subscribedSkus``: Microsoft Sentinel,
Log Analytics, Defender for Cloud CSPM, and Defender for Cloud servers.
This module probes Azure Resource Manager surfaces to observe whether each
is actually configured and returns a :class:`ConsumptionObservation` the
collection runner merges into SKU-resolved ownership.

Required RBAC (documented here; report cards land in WS2-B): Microsoft
Sentinel Reader on the workspace (onboarding state + workspace GET),
Security Reader on the subscription (Defender for Cloud pricings).

Probe API references:

- Sentinel Onboarding States - Get (api-version 2024-03-01):
  https://learn.microsoft.com/rest/api/securityinsights/sentinel-onboarding-states/get?view=rest-securityinsights-2024-03-01
- Log Analytics Workspaces - Get (api-version 2022-10-01):
  https://learn.microsoft.com/rest/api/loganalytics/workspaces/get?view=rest-loganalytics-2022-10-01
- Defender for Cloud Pricings - List (api-version 2024-01-01):
  https://learn.microsoft.com/rest/api/defenderforcloud/pricings/list?view=rest-defenderforcloud-2024-01-01
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from licenselens.auth import AuthContext
from licenselens.collectors.arm import (
    encode_resource_path,
    subscription_id_from_resource_id,
)
from licenselens.collectors.arm_selective import collect_defender_for_cloud_pricings
from licenselens.errors import AuthError, GraphError

if TYPE_CHECKING:
    from licenselens.collectors.arm import ArmClient

__all__ = [
    "CONSUMPTION_CAPABILITY_IDS",
    "ConsumptionObservation",
    "DEMO_WORKSPACE_RESOURCE_ID",
    "NO_SCOPE_WARNING",
    "NO_WORKSPACE_WARNING",
    "observe_consumption_entitlements",
]

NO_SCOPE_WARNING: Final = (
    "No Azure scope supplied; pass --workspace-resource-id or "
    "--subscription-id to assess Sentinel / Defender for Cloud."
)
NO_WORKSPACE_WARNING: Final = (
    "Sentinel and Log Analytics entitlement not assessed: no workspace resource id was supplied."
)
CONSUMPTION_CAPABILITY_IDS: Final = (
    "defender_for_cloud_cspm",
    "defender_for_cloud_servers",
    "log_analytics",
    "microsoft_sentinel",
)
SENTINEL_ONBOARDING_API: Final = "2024-03-01"
WORKSPACE_API: Final = "2022-10-01"
DEMO_WORKSPACE_RESOURCE_ID: Final = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/demo-rg/providers/Microsoft.OperationalInsights/"
    "workspaces/demo-sentinel"
)


@dataclass(frozen=True, slots=True)
class ConsumptionObservation:
    """Result of observing consumption entitlements in Azure."""

    owned: frozenset[str]
    unknown: frozenset[str]
    evidence: dict[str, Any]
    warnings: tuple[str, ...]


def _probe_get(client: ArmClient, path: str) -> tuple[int, dict[str, Any] | None]:
    """GET one ARM resource, classifying 404 without raising.

    Returns ``(200, payload)`` on success and ``(404, None)`` when the
    resource does not exist.  Any other failure (denied, throttled, network)
    raises :class:`GraphError` for the caller to classify as unknown.
    """
    try:
        return 200, client.get(path)
    except GraphError as exc:
        if exc.status_code == 404:
            return 404, None
        raise


def _probe_sentinel(
    client: ArmClient,
    workspace_resource_id: str,
    evidence: dict[str, Any],
) -> bool:
    """Probe the ``default`` Sentinel onboarding state on the workspace.

    A 200 proves the workspace is onboarded to Microsoft Sentinel; 404 means
    not onboarded (not owned, not unknown).  Learn:
    https://learn.microsoft.com/rest/api/securityinsights/sentinel-onboarding-states/get?view=rest-securityinsights-2024-03-01
    """
    path = (
        f"{encode_resource_path(workspace_resource_id)}"
        "/providers/Microsoft.SecurityInsights/onboardingStates/default"
        f"?api-version={SENTINEL_ONBOARDING_API}"
    )
    status, _payload = _probe_get(client, path)
    evidence["microsoft_sentinel"] = {"status": status}
    return status == 200


def _probe_log_analytics(
    client: ArmClient,
    workspace_resource_id: str,
    evidence: dict[str, Any],
) -> bool:
    """Probe the Log Analytics workspace itself.

    A 200 proves a provisioned (billable) workspace exists, i.e. Log
    Analytics consumption entitlement; 404 means no such workspace.  Learn:
    https://learn.microsoft.com/rest/api/loganalytics/workspaces/get?view=rest-loganalytics-2022-10-01
    """
    path = f"{encode_resource_path(workspace_resource_id)}?api-version={WORKSPACE_API}"
    status, payload = _probe_get(client, path)
    detail: dict[str, Any] = {"status": status}
    if payload is not None:
        properties = payload.get("properties")
        if isinstance(properties, dict):
            detail["customer_id"] = properties.get("customerId")
            sku = properties.get("sku")
            if isinstance(sku, dict):
                detail["sku"] = sku.get("name")
            detail["retention_in_days"] = properties.get("retentionInDays")
    evidence["log_analytics"] = detail
    return status == 200


def _probe_defender_pricings(
    client: ArmClient,
    subscription_id: str,
    evidence: dict[str, Any],
) -> set[str]:
    """Probe Defender for Cloud plan pricings on the subscription.

    ``CloudPosture`` on the Standard tier proves the CSPM capability and
    ``VirtualMachines`` on Standard proves the servers capability (subPlan
    P1/P2 recorded); Free or absent plans mean not owned.  Learn:
    https://learn.microsoft.com/rest/api/defenderforcloud/pricings/list?view=rest-defenderforcloud-2024-01-01
    """
    rows = collect_defender_for_cloud_pricings(client, subscription_id)
    owned: set[str] = set()
    tiers: dict[str, str] = {}
    sub_plan: str | None = None
    for row in rows:
        name = str(row.get("name") or "")
        props = row.get("properties")
        tier = ""
        if isinstance(props, dict):
            tier = str(props.get("pricingTier") or "")
        if not name:
            continue
        tiers[name] = tier
        standard = tier.lower() == "standard"
        if name == "CloudPosture" and standard:
            owned.add("defender_for_cloud_cspm")
        elif name == "VirtualMachines" and standard:
            owned.add("defender_for_cloud_servers")
            if isinstance(props, dict) and props.get("subPlan") is not None:
                sub_plan = str(props["subPlan"])
    evidence["defender_for_cloud_pricings"] = {
        "status": 200,
        "cloud_posture_tier": tiers.get("CloudPosture"),
        "virtual_machines_tier": tiers.get("VirtualMachines"),
        "virtual_machines_sub_plan": sub_plan,
    }
    return owned


def _observe_live(
    client: ArmClient,
    *,
    workspace_resource_id: str | None,
    subscription_id: str | None,
) -> tuple[set[str], set[str], dict[str, Any], list[str]]:
    """Run every live probe; collect owned/unknown/evidence/warnings."""
    owned: set[str] = set()
    unknown: set[str] = set()
    evidence: dict[str, Any] = {}
    warnings: list[str] = []
    if workspace_resource_id:
        try:
            if _probe_sentinel(client, workspace_resource_id, evidence):
                owned.add("microsoft_sentinel")
        except GraphError as exc:
            unknown.add("microsoft_sentinel")
            evidence["microsoft_sentinel"] = {"status": exc.status_code}
            warnings.append(f"Microsoft Sentinel entitlement not assessed: {exc}")
        try:
            if _probe_log_analytics(client, workspace_resource_id, evidence):
                owned.add("log_analytics")
        except GraphError as exc:
            unknown.add("log_analytics")
            evidence["log_analytics"] = {"status": exc.status_code}
            warnings.append(f"Log Analytics entitlement not assessed: {exc}")
    else:
        unknown.update({"microsoft_sentinel", "log_analytics"})
        warnings.append(NO_WORKSPACE_WARNING)
    if subscription_id:
        try:
            owned.update(_probe_defender_pricings(client, subscription_id, evidence))
        except GraphError as exc:
            if exc.status_code == 404:
                evidence["defender_for_cloud_pricings"] = {"status": 404}
            else:
                unknown.update({"defender_for_cloud_cspm", "defender_for_cloud_servers"})
                evidence["defender_for_cloud_pricings"] = {"status": exc.status_code}
                warnings.append(f"Defender for Cloud entitlement not assessed: {exc}")
    return owned, unknown, evidence, warnings


def _observe_dry_run() -> ConsumptionObservation:
    """Canned demo observation: exactly Sentinel + Log Analytics owned."""
    return ConsumptionObservation(
        owned=frozenset({"microsoft_sentinel", "log_analytics"}),
        unknown=frozenset(),
        evidence={
            "microsoft_sentinel": {
                "status": 200,
                "workspace_resource_id": DEMO_WORKSPACE_RESOURCE_ID,
            },
            "log_analytics": {
                "status": 200,
                "workspace_resource_id": DEMO_WORKSPACE_RESOURCE_ID,
                "customer_id": "00000000-0000-0000-0000-000000000000",
                "sku": "PerGB2018",
                "retention_in_days": 30,
            },
        },
        warnings=(),
    )


def _all_unknown(warning: str) -> ConsumptionObservation:
    return ConsumptionObservation(
        owned=frozenset(),
        unknown=frozenset(CONSUMPTION_CAPABILITY_IDS),
        evidence={},
        warnings=(warning,),
    )


def observe_consumption_entitlements(
    auth: AuthContext,
    *,
    workspace_resource_id: str | None,
    subscription_id: str | None,
    arm_client: ArmClient | None = None,
    dry_run: bool = False,
) -> ConsumptionObservation:
    """Observe consumption-metered entitlements from Azure ARM surfaces.

    Probes are independent: each 404 means "not owned" (no warning), each
    other failure marks the capability ``unknown`` with a warning naming the
    probe, and the function never raises.  ``dry_run`` short-circuits to a
    canned demo observation with no ARM calls.
    """
    if dry_run:
        return _observe_dry_run()
    subscription = subscription_id or (
        subscription_id_from_resource_id(workspace_resource_id) if workspace_resource_id else None
    )
    if not workspace_resource_id and not subscription:
        return _all_unknown(NO_SCOPE_WARNING)
    client = arm_client
    owns_client = client is None
    try:
        if owns_client:
            # Deferred import: test seams patch ``licenselens.collectors.arm.ArmClient``
            # at call time, so the class must be resolved per call, not at import.
            from licenselens.collectors.arm import ArmClient

            client = ArmClient(auth)
        owned, unknown, evidence, warnings = _observe_live(
            client,
            workspace_resource_id=workspace_resource_id,
            subscription_id=subscription,
        )
    except AuthError as exc:
        return _all_unknown(f"Azure entitlement probes could not run: {exc}")
    finally:
        if owns_client and client is not None:
            client.close()
    return ConsumptionObservation(
        owned=frozenset(owned),
        unknown=frozenset(unknown),
        evidence=evidence,
        warnings=tuple(warnings),
    )
