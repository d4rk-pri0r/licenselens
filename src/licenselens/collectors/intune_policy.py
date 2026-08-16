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
_MAX_TAMPER_DEVICES = 10

_ASR_RULE_KEY = "attacksurfacereductionrules"

_SURFACES = (
    "managed_devices",
    "compliance_policies",
    "configuration_policies",
    "atp_onboarding_state",
    "device_configurations",
    "asr_policies",
    "compliance_state_summary",
    "app_protection_policies",
    "tamper_device_state",
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
        return _bundle([], [], [], None, [], [], None, [], _EMPTY_TAMPER_STATE, licensed_units, False, errors)

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

    try:
        device_configs = client.get_list("/deviceManagement/deviceConfigurations", max_pages=30)
    except GraphError as exc:
        device_configs = []
        errors["device_configurations"] = str(exc)

    atp: dict[str, Any] | None = None
    try:
        atp = collect_intune_atp_onboarding_state(client)
    except GraphError as exc:
        errors["atp_onboarding_state"] = str(exc)

    asr_policy_entries, asr_error = _collect_asr_policies(client, config, max_policy_detail)
    if asr_error:
        errors["asr_policies"] = asr_error

    state_summary: dict[str, Any] | None = None
    try:
        data = client.get("/deviceManagement/deviceCompliancePolicyDeviceStateSummary")
        state_summary = data if isinstance(data, dict) else None
    except GraphError as exc:
        errors["compliance_state_summary"] = str(exc)

    try:
        app_protections = client.get_list("/deviceAppManagement/managedAppProtections", max_pages=30)
    except GraphError as exc:
        app_protections = []
        errors["app_protection_policies"] = str(exc)

    tamper_state = _collect_tamper_device_state(client, devices)

    enriched = [
        _enrich_compliance_policy(client, policy) for policy in compliance[:max_policy_detail]
    ]
    enriched_configs = [
        _enrich_device_configuration(client, cfg) for cfg in device_configs[:max_policy_detail]
    ]
    enriched_app_protections = [
        _enrich_app_protection(client, policy) for policy in app_protections[:max_policy_detail]
    ]
    truncated = len(compliance) > max_policy_detail
    return _bundle(
        devices,
        enriched,
        config,
        atp,
        enriched_configs,
        asr_policy_entries,
        state_summary,
        enriched_app_protections,
        tamper_state,
        licensed_units,
        truncated,
        errors,
    )


def _bundle(
    devices: list[dict[str, Any]],
    compliance: list[dict[str, Any]],
    config: list[dict[str, Any]],
    atp: dict[str, Any] | None,
    device_configs: list[dict[str, Any]],
    asr_policies: list[dict[str, Any]],
    state_summary: dict[str, Any] | None,
    app_protections: list[dict[str, Any]],
    tamper_state: dict[str, Any],
    licensed_units: int | None,
    truncated: bool,
    errors: dict[str, str],
) -> dict[str, Any]:
    return {
        "managed_devices": devices,
        "compliance_policies": compliance,
        "configuration_policies": config,
        "atp_onboarding_state": atp,
        "device_configurations": device_configs,
        "asr_policies": asr_policies,
        "compliance_state_summary": state_summary,
        "app_protection_policies": app_protections,
        "tamper_device_state": tamper_state,
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


_EMPTY_TAMPER_STATE: dict[str, Any] = {
    "sampled": 0,
    "enabled": 0,
    "disabled": 0,
    "unknown": 0,
    "unreadable": 0,
}


def _is_asr_family(policy: dict[str, Any]) -> bool:
    ref = policy.get("templateReference") or {}
    family = str(ref.get("templateFamily") or "") if isinstance(ref, dict) else ""
    return "attacksurfacereduction" in family.lower()


def _collect_asr_policies(
    client: GraphClient,
    config: list[dict[str, Any]],
    max_policy_detail: int,
) -> tuple[list[dict[str, Any]], str]:
    """Unified ASR policy list from the endpointSecurity path, falling back to
    settings-catalog ASR configuration policies when the legacy path is empty
    or unreadable (the newer policy infrastructure hosts ASR there)."""
    asr_raw: list[dict[str, Any]] | None = None
    read_error = ""
    try:
        asr_raw = client.get_list(
            "/deviceManagement/endpointSecurity/attackSurfaceReductionPolicies", max_pages=30
        )
    except GraphError as exc:
        asr_raw = None
        read_error = str(exc)

    if asr_raw:
        return (
            [_enrich_endpoint_security_asr_policy(client, policy) for policy in asr_raw[:max_policy_detail]],
            "",
        )

    asr_candidates = [policy for policy in config if _is_asr_family(policy)]
    if asr_candidates:
        return (
            [_enrich_configuration_asr_policy(client, policy) for policy in asr_candidates[:max_policy_detail]],
            "",
        )
    if asr_raw is None:
        return [], f"ASR policy surfaces unreadable: {read_error}"
    return [], ""


def _enrich_endpoint_security_asr_policy(
    client: GraphClient, policy: dict[str, Any]
) -> dict[str, Any]:
    pid = str(policy.get("id") or "")
    entry: dict[str, Any] = {
        "id": pid,
        "displayName": str(policy.get("displayName") or pid),
        "source": "endpointSecurity",
        "assigned": False,
        "assignments": [],
        "assignments_error": False,
        "rule_count": 0,
        "rules_error": False,
    }
    if not pid:
        return entry
    base = f"/deviceManagement/endpointSecurity/attackSurfaceReductionPolicies/{pid}"
    entry["assignments"] = _safe_list(client, f"{base}/assignments")
    entry["assignments_error"] = entry["assignments"] is None
    entry["assignments"] = entry["assignments"] or []
    entry["assigned"] = bool(entry["assignments"])

    settings = policy.get("settings") if isinstance(policy.get("settings"), list) else None
    if settings is None:
        settings = _safe_list(client, f"{base}/settings")
    if settings is None:
        entry["rules_error"] = True
    else:
        entry["rule_count"] = _count_asr_rules(settings)
    return entry


def _enrich_configuration_asr_policy(
    client: GraphClient, policy: dict[str, Any]
) -> dict[str, Any]:
    pid = str(policy.get("id") or "")
    entry: dict[str, Any] = {
        "id": pid,
        "displayName": str(policy.get("name") or pid),
        "source": "configurationPolicies",
        "assigned": bool(policy.get("isAssigned")),
        "assignments": [],
        "assignments_error": False,
        "rule_count": 0,
        "rules_error": False,
    }
    if "isAssigned" not in policy and pid:
        entry["assignments"] = _safe_list(client, f"/deviceManagement/configurationPolicies/{pid}/assignments")
        entry["assignments_error"] = entry["assignments"] is None
        entry["assignments"] = entry["assignments"] or []
        entry["assigned"] = bool(entry["assignments"])
    if not pid:
        return entry
    settings = _safe_list(client, f"/deviceManagement/configurationPolicies/{pid}/settings")
    if settings is None:
        entry["rules_error"] = True
    else:
        entry["rule_count"] = _count_asr_rules(settings)
    return entry


def _count_asr_rules(settings: list[dict[str, Any]]) -> int:
    """Count distinct ASR rule setting definitions inside a policy's settings."""
    seen: set[str] = set()
    for setting in settings:
        if not isinstance(setting, dict):
            continue
        instance = setting.get("settingInstance")
        for candidate in (instance, setting):
            if isinstance(candidate, dict):
                definition_id = str(candidate.get("settingDefinitionId") or "").lower()
                if _is_asr_rule_definition(definition_id):
                    seen.add(definition_id)
            for child in _iter_setting_children(candidate):
                definition_id = str(child.get("settingDefinitionId") or "").lower()
                if _is_asr_rule_definition(definition_id):
                    seen.add(definition_id)
    return len(seen)


def _is_asr_rule_definition(definition_id: str) -> bool:
    marker = definition_id.find(_ASR_RULE_KEY)
    return marker >= 0 and len(definition_id) > marker + len(_ASR_RULE_KEY)


def _iter_setting_children(instance: Any):
    stack = [instance]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        for container in ("groupSettingCollectionValue", "children"):
            children = node.get(container)
            if isinstance(children, list):
                for child in children:
                    if isinstance(child, dict):
                        yield child
                        stack.append(child)


def _enrich_device_configuration(
    client: GraphClient, cfg: dict[str, Any]
) -> dict[str, Any]:
    cid = str(cfg.get("id") or "")
    entry: dict[str, Any] = {
        "id": cid,
        "displayName": str(cfg.get("displayName") or cid),
        "odata_type": str(cfg.get("@odata.type") or ""),
        "bitLockerEncryptDevice": cfg.get("bitLockerEncryptDevice"),
        "assigned": False,
        "assignments": [],
        "assignments_error": False,
    }
    if not cid:
        return entry
    entry["assignments"] = _safe_list(client, f"/deviceManagement/deviceConfigurations/{cid}/assignments")
    entry["assignments_error"] = entry["assignments"] is None
    entry["assignments"] = entry["assignments"] or []
    entry["assigned"] = bool(entry["assignments"])
    return entry


def _enrich_app_protection(client: GraphClient, policy: dict[str, Any]) -> dict[str, Any]:
    pid = str(policy.get("id") or "")
    odata = str(policy.get("@odata.type") or "")
    entry: dict[str, Any] = {
        "id": pid,
        "displayName": str(policy.get("displayName") or pid),
        "odata_type": odata,
        "assignment_mode": "targeted",
        "assigned": False,
        "assignments": [],
        "assignments_error": False,
    }
    lowered = odata.lower()
    if "defaultmanagedappprotection" in lowered:
        # Default policies apply org-wide; there is no assignment list.
        entry["assignment_mode"] = "default"
        entry["assigned"] = True
        return entry
    base = ""
    if "androidmanagedappprotection" in lowered:
        base = "androidManagedAppProtections"
    elif "iosmanagedappprotection" in lowered:
        base = "iosManagedAppProtections"
    if not base:
        entry["assignment_mode"] = "unknown"
        return entry
    if not pid:
        return entry
    entry["assignments"] = _safe_list(client, f"/deviceAppManagement/{base}/{pid}/assignments")
    entry["assignments_error"] = entry["assignments"] is None
    entry["assignments"] = entry["assignments"] or []
    entry["assigned"] = bool(entry["assignments"])
    return entry


def _collect_tamper_device_state(
    client: GraphClient, devices: list[dict[str, Any]]
) -> dict[str, Any]:
    """Aggregate tamperProtectionEnabled from a bounded sample of Windows devices."""
    state: dict[str, Any] = dict(_EMPTY_TAMPER_STATE)
    windows = [
        device
        for device in devices
        if "windows" in str(device.get("operatingSystem") or "").lower()
    ]
    for device in windows[:_MAX_TAMPER_DEVICES]:
        did = str(device.get("id") or "")
        if not did:
            continue
        state["sampled"] += 1
        try:
            data = client.get(f"/deviceManagement/managedDevices/{did}/windowsProtectionState")
        except GraphError:
            state["unreadable"] += 1
            state["unknown"] += 1
            continue
        flag = data.get("tamperProtectionEnabled") if isinstance(data, dict) else None
        if flag is True:
            state["enabled"] += 1
        elif flag is False:
            state["disabled"] += 1
        else:
            state["unknown"] += 1
    return state


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
    "device_configurations": [
        {
            "id": "cfg-bl",
            "displayName": "BitLocker encryption",
            "odata_type": "#microsoft.graph.windows10EndpointProtectionConfiguration",
            "bitLockerEncryptDevice": True,
            "assigned": True,
            "assignments": [{"id": "ba1", "target": {"groupId": "g-all"}}],
            "assignments_error": False,
        },
        {
            "id": "cfg-atp",
            "displayName": "Defender ATP config",
            "odata_type": "#microsoft.graph.windowsDefenderAdvancedThreatProtectionConfiguration",
            "bitLockerEncryptDevice": None,
            "assigned": True,
            "assignments": [{"id": "ba2", "target": {"groupId": "g-all"}}],
            "assignments_error": False,
        },
    ],
    "asr_policies": [
        {
            "id": "asr-1",
            "displayName": "Endpoint security - ASR rules",
            "source": "endpointSecurity",
            "assigned": True,
            "assignments": [{"id": "aa1", "target": {"groupId": "g-all"}}],
            "assignments_error": False,
            "rule_count": 3,
            "rules_error": False,
        }
    ],
    "compliance_state_summary": {
        "id": "state-summary",
        "compliantDeviceCount": 90,
        "nonCompliantDeviceCount": 0,
        "unknownDeviceCount": 0,
        "errorDeviceCount": 0,
        "conflictDeviceCount": 0,
        "inGracePeriodCount": 0,
        "notApplicableDeviceCount": 8,
    },
    "app_protection_policies": [
        {
            "id": "mam-ios",
            "displayName": "iOS app protection",
            "odata_type": "#microsoft.graph.iosManagedAppProtection",
            "assignment_mode": "targeted",
            "assigned": True,
            "assignments": [{"id": "ma1", "target": {"groupId": "g-all"}}],
            "assignments_error": False,
        },
        {
            "id": "mam-android",
            "displayName": "Android app protection",
            "odata_type": "#microsoft.graph.androidManagedAppProtection",
            "assignment_mode": "targeted",
            "assigned": True,
            "assignments": [{"id": "ma2", "target": {"groupId": "g-all"}}],
            "assignments_error": False,
        },
    ],
    "tamper_device_state": {
        "sampled": 2,
        "enabled": 2,
        "disabled": 0,
        "unknown": 0,
        "unreadable": 0,
    },
    "licensed_units": 100,
    "truncated": False,
    "errors": {
        "managed_devices": "",
        "compliance_policies": "",
        "configuration_policies": "",
        "atp_onboarding_state": "",
        "device_configurations": "",
        "asr_policies": "",
        "compliance_state_summary": "",
        "app_protection_policies": "",
        "tamper_device_state": "",
    },
}
