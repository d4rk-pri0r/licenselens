"""Intune policy/assignment/connector collection bundle (Todo 22).

Collects compliance-policy assignment and noncompliance-action detail, endpoint
security configuration policies, managed-device inventory, and the Intune-MDE
onboarding summary. Each surface is collected best-effort and surfaced through
an ``errors`` map so evaluators can downgrade to manual/partial instead of
fabricating a gap when an API proves nothing.
"""

from __future__ import annotations

from typing import Any

from licenselens.collectors.contracts import CloudEnvironment
from licenselens.errors import GraphError
from licenselens.graph import GraphClient
from licenselens.models import SubscribedSku

__all__ = [
    "DEMO_INTUNE_EVIDENCE_BUNDLE",
    "INTUNE_PLAN_HINTS",
    "INTUNE_SKU_HINTS",
    "collect_intune_atp_onboarding_state",
    "collect_intune_evidence_bundle",
    "intune_licensed_units",
]

INTUNE_PLAN_HINTS: tuple[str, ...] = (
    "INTUNE_A",
    "INTUNE_A_VL",
    "MDM_SALES_COLLABORATION",
)

INTUNE_SKU_HINTS: tuple[str, ...] = (
    "SPE_E3",
    "SPE_E5",
    "ENTERPRISEPACK",
    "ENTERPRISEPREMIUM",
    "EMSPREMIUM",
    "INTUNE_A",
)

_MAX_POLICY_DETAIL = 15

_SURFACES = (
    "managed_devices",
    "compliance_policies",
    "configuration_policies",
    "atp_onboarding_state",
)


def intune_licensed_units(skus: list[SubscribedSku]) -> int | None:
    """Best-effort prepaid units attributable to Intune across active SKUs."""
    total = 0
    found = False
    for sku in skus:
        part = (sku.sku_part_number or "").upper()
        plans = {p.service_plan_name.upper() for p in sku.service_plans if p.service_plan_name}
        if part in INTUNE_SKU_HINTS or bool(plans & set(INTUNE_PLAN_HINTS)):
            found = True
            if sku.prepaid_units is not None:
                total += int(sku.prepaid_units)
    return total if found else None


def collect_intune_atp_onboarding_state(client: GraphClient) -> dict[str, Any]:
    """Intune-MDE connector onboarding summary (single resource)."""
    data = client.get("/deviceManagement/advancedThreatProtectionOnboardingStateSummary")
    return data if isinstance(data, dict) else {}


def collect_intune_evidence_bundle(
    client: GraphClient,
    *,
    licensed_units: int | None = None,
    max_policy_detail: int = _MAX_POLICY_DETAIL,
) -> dict[str, Any]:
    """Collect Intune surfaces best-effort; per-surface failures live in ``errors``."""
    errors: dict[str, str] = {surface: "" for surface in _SURFACES}

    if getattr(client, "cloud", None) is CloudEnvironment.CHINA:
        for surface in _SURFACES:
            errors[surface] = "Intune device management is not supported in this cloud."
        return _bundle([], [], [], None, licensed_units, False, errors)

    try:
        devices = client.get_list("/deviceManagement/managedDevices", max_pages=20)
    except GraphError as exc:
        devices = []
        errors["managed_devices"] = str(exc)

    try:
        compliance = client.get_list("/deviceManagement/deviceCompliancePolicies", max_pages=30)
    except GraphError as exc:
        compliance = []
        errors["compliance_policies"] = str(exc)

    try:
        config = client.get_list("/deviceManagement/configurationPolicies", max_pages=30)
    except GraphError as exc:
        config = []
        errors["configuration_policies"] = str(exc)

    atp: dict[str, Any] | None = None
    try:
        atp = collect_intune_atp_onboarding_state(client)
    except GraphError as exc:
        errors["atp_onboarding_state"] = str(exc)

    enriched = [
        _enrich_compliance_policy(client, policy) for policy in compliance[:max_policy_detail]
    ]
    truncated = len(compliance) > max_policy_detail
    return _bundle(devices, enriched, config, atp, licensed_units, truncated, errors)


def _bundle(
    devices: list[dict[str, Any]],
    compliance: list[dict[str, Any]],
    config: list[dict[str, Any]],
    atp: dict[str, Any] | None,
    licensed_units: int | None,
    truncated: bool,
    errors: dict[str, str],
) -> dict[str, Any]:
    return {
        "managed_devices": devices,
        "compliance_policies": compliance,
        "configuration_policies": config,
        "atp_onboarding_state": atp,
        "licensed_units": licensed_units,
        "truncated": truncated,
        "errors": errors,
    }


def _enrich_compliance_policy(client: GraphClient, policy: dict[str, Any]) -> dict[str, Any]:
    pid = str(policy.get("id") or "")
    entry: dict[str, Any] = {
        "id": pid,
        "displayName": str(policy.get("displayName") or pid),
        "platforms": str(policy.get("platforms") or ""),
        "assigned": False,
        "assignments": [],
        "assignments_error": False,
        "has_noncompliance_action": False,
        "noncompliance_actions": [],
        "noncompliance_actions_error": False,
    }
    if not pid:
        return entry
    entry["assignments"] = _safe_list(
        client, f"/deviceManagement/deviceCompliancePolicies/{pid}/assignments"
    )
    entry["assignments_error"] = entry["assignments"] is None
    entry["assignments"] = entry["assignments"] or []
    entry["assigned"] = bool(entry["assignments"])

    entry["noncompliance_actions"] = _safe_list(
        client, f"/deviceManagement/deviceCompliancePolicies/{pid}/scheduledActionsForRule"
    )
    entry["noncompliance_actions_error"] = entry["noncompliance_actions"] is None
    entry["noncompliance_actions"] = entry["noncompliance_actions"] or []
    entry["has_noncompliance_action"] = bool(entry["noncompliance_actions"])
    return entry


def _safe_list(client: GraphClient, path: str) -> list[dict[str, Any]] | None:
    """Return the list, or ``None`` when the read failed (unreadable detail)."""
    try:
        return client.get_list(path, max_pages=5)
    except GraphError:
        return None


DEMO_INTUNE_EVIDENCE_BUNDLE: dict[str, Any] = {
    "managed_devices": [
        {
            "id": "dev-1",
            "deviceName": "LAPTOP-1",
            "complianceState": "compliant",
            "operatingSystem": "Windows",
        },
        {
            "id": "dev-2",
            "deviceName": "PHONE-1",
            "complianceState": "compliant",
            "operatingSystem": "iOS",
        },
    ],
    "compliance_policies": [
        {
            "id": "comp-1",
            "displayName": "Windows compliance baseline",
            "platforms": "windows10",
            "assigned": True,
            "assignments": [{"id": "a1", "target": {"groupId": "g-all"}}],
            "assignments_error": False,
            "has_noncompliance_action": True,
            "noncompliance_actions": [{"id": "sar1"}],
            "noncompliance_actions_error": False,
        },
        {
            "id": "comp-2",
            "displayName": "iOS compliance",
            "platforms": "ios",
            "assigned": True,
            "assignments": [{"id": "a2", "target": {"groupId": "g-all"}}],
            "assignments_error": False,
            "has_noncompliance_action": True,
            "noncompliance_actions": [{"id": "sar2"}],
            "noncompliance_actions_error": False,
        },
    ],
    "configuration_policies": [
        {
            "id": "ep-av",
            "name": "Endpoint security - Antivirus",
            "templateReference": {"templateFamily": "endpointSecurityAntivirus"},
        },
        {
            "id": "ep-fw",
            "name": "Endpoint security - Firewall",
            "templateReference": {"templateFamily": "endpointSecurityFirewall"},
        },
        {
            "id": "ep-de",
            "name": "Endpoint security - Disk encryption",
            "templateReference": {"templateFamily": "endpointSecurityDiskEncryption"},
        },
        {
            "id": "ep-asr",
            "name": "Endpoint security - ASR",
            "templateReference": {"templateFamily": "endpointSecurityAttackSurfaceReduction"},
        },
        {
            "id": "ep-bl",
            "name": "Endpoint security - Security baseline",
            "templateReference": {"templateFamily": "endpointSecuritySecurityBaselines"},
        },
    ],
    "atp_onboarding_state": {
        "onboardedDeviceCount": 2,
        "unknownDeviceCount": 0,
        "unhealthyDeviceCount": 0,
    },
    "licensed_units": 100,
    "truncated": False,
    "errors": {
        "managed_devices": "",
        "compliance_policies": "",
        "configuration_policies": "",
        "atp_onboarding_state": "",
    },
}
