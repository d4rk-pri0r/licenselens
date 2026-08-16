"""Todo 17 endpoint depth checks: ASR rules, BitLocker, tamper protection,
compliance enforcement state, and MAM app protection."""

from __future__ import annotations

import copy
from typing import Any

from licenselens.auth import AuthMode, build_auth_context
from licenselens.collectors.contracts import CloudEnvironment
from licenselens.collectors.intune_policy import (
    DEMO_INTUNE_EVIDENCE_BUNDLE,
    collect_intune_evidence_bundle,
)
from licenselens.engine.loader import load_checks
from licenselens.engine.runner import _evaluate_check, run_scan
from licenselens.evaluators.endpoint_intune_depth import (
    evaluate_endpoint_asr_rules,
    evaluate_endpoint_bitlocker_policy,
    evaluate_endpoint_compliance_enforcement,
    evaluate_endpoint_mam_app_protection,
    evaluate_endpoint_tamper_protection,
)
from licenselens.models import CheckDefinition, FindingStatus, Workload
from tests.fake_clients import FakeGraphClient, error, ok

_DEPTH_CHECKS = (
    "ep-asr-rules",
    "ep-bitlocker-policy",
    "ep-tamper-protection",
    "ep-compliance-enforcement",
    "ep-mam-app-protection",
)


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=Workload.ENDPOINT)


def _demo() -> dict[str, Any]:
    return {"intune_bundle": copy.deepcopy(DEMO_INTUNE_EVIDENCE_BUNDLE)}


def _bundle(evidence: dict[str, Any]) -> dict[str, Any]:
    return evidence["intune_bundle"]


def _surface_error(evidence: dict[str, Any], surface: str, message: str = "403 Forbidden") -> None:
    _bundle(evidence)["errors"][surface] = message


def test_demo_endpoint_depth_matrix_produces_ok() -> None:
    evidence = _demo()
    assert (
        evaluate_endpoint_asr_rules(_check("ep-asr-rules"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_endpoint_bitlocker_policy(_check("ep-bitlocker-policy"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_endpoint_tamper_protection(_check("ep-tamper-protection"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_endpoint_compliance_enforcement(
            _check("ep-compliance-enforcement"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_endpoint_mam_app_protection(_check("ep-mam-app-protection"), evidence).status
        is FindingStatus.OK
    )


# ---------------------------------------------------------------------------
# ep-asr-rules
# ---------------------------------------------------------------------------


def test_asr_no_policies_is_gap() -> None:
    evidence = _demo()
    _bundle(evidence)["asr_policies"] = []
    assert evaluate_endpoint_asr_rules(_check("ep-asr-rules"), evidence).status is FindingStatus.GAP


def test_asr_unassigned_is_gap() -> None:
    evidence = _demo()
    for policy in _bundle(evidence)["asr_policies"]:
        policy["assigned"] = False
        policy["assignments"] = []
    assert evaluate_endpoint_asr_rules(_check("ep-asr-rules"), evidence).status is FindingStatus.GAP


def test_asr_assigned_without_rules_is_partial() -> None:
    evidence = _demo()
    for policy in _bundle(evidence)["asr_policies"]:
        policy["rule_count"] = 0
    result = evaluate_endpoint_asr_rules(_check("ep-asr-rules"), evidence)
    assert result.status is FindingStatus.PARTIAL


def test_asr_unreadable_rules_is_partial() -> None:
    evidence = _demo()
    for policy in _bundle(evidence)["asr_policies"]:
        policy["rules_error"] = True
    result = evaluate_endpoint_asr_rules(_check("ep-asr-rules"), evidence)
    assert result.status is FindingStatus.PARTIAL


def test_asr_assignment_unreadable_is_partial() -> None:
    evidence = _demo()
    _bundle(evidence)["asr_policies"][0]["assignments_error"] = True
    result = evaluate_endpoint_asr_rules(_check("ep-asr-rules"), evidence)
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.GAP


def test_asr_surface_error_is_partial_not_gap() -> None:
    evidence = _demo()
    _surface_error(evidence, "asr_policies")
    result = evaluate_endpoint_asr_rules(_check("ep-asr-rules"), evidence)
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.GAP


def test_asr_partial_rules_among_assigned_is_partial() -> None:
    evidence = _demo()
    _bundle(evidence)["asr_policies"].append(
        {
            "id": "asr-2",
            "displayName": "Empty ASR shell",
            "source": "endpointSecurity",
            "assigned": True,
            "assignments": [{"id": "aa2"}],
            "assignments_error": False,
            "rule_count": 0,
            "rules_error": False,
        }
    )
    result = evaluate_endpoint_asr_rules(_check("ep-asr-rules"), evidence)
    assert result.status is FindingStatus.PARTIAL


# ---------------------------------------------------------------------------
# ep-bitlocker-policy
# ---------------------------------------------------------------------------


def test_bitlocker_no_config_is_gap() -> None:
    evidence = _demo()
    _bundle(evidence)["device_configurations"] = []
    result = evaluate_endpoint_bitlocker_policy(_check("ep-bitlocker-policy"), evidence)
    assert result.status is FindingStatus.GAP


def test_bitlocker_unassigned_is_gap() -> None:
    evidence = _demo()
    for cfg in _bundle(evidence)["device_configurations"]:
        if cfg["id"] == "cfg-bl":
            cfg["assigned"] = False
            cfg["assignments"] = []
    result = evaluate_endpoint_bitlocker_policy(_check("ep-bitlocker-policy"), evidence)
    assert result.status is FindingStatus.GAP


def test_bitlocker_assignment_unreadable_is_partial() -> None:
    evidence = _demo()
    for cfg in _bundle(evidence)["device_configurations"]:
        if cfg["id"] == "cfg-bl":
            cfg["assignments_error"] = True
    result = evaluate_endpoint_bitlocker_policy(_check("ep-bitlocker-policy"), evidence)
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.GAP


def test_bitlocker_ignores_non_encryption_configs() -> None:
    evidence = _demo()
    _bundle(evidence)["device_configurations"] = [
        {
            "id": "cfg-other",
            "displayName": "Wi-Fi profile",
            "odata_type": "#microsoft.graph.windowsWifiConfiguration",
            "bitLockerEncryptDevice": None,
            "assigned": True,
            "assignments": [{"id": "x1"}],
            "assignments_error": False,
        }
    ]
    result = evaluate_endpoint_bitlocker_policy(_check("ep-bitlocker-policy"), evidence)
    assert result.status is FindingStatus.GAP


def test_bitlocker_name_match_is_detected() -> None:
    evidence = _demo()
    _bundle(evidence)["device_configurations"] = [
        {
            "id": "cfg-legacy",
            "displayName": "BitLocker baseline",
            "odata_type": "#microsoft.graph.windows10GeneralConfiguration",
            "bitLockerEncryptDevice": None,
            "assigned": True,
            "assignments": [{"id": "x1"}],
            "assignments_error": False,
        }
    ]
    result = evaluate_endpoint_bitlocker_policy(_check("ep-bitlocker-policy"), evidence)
    assert result.status is FindingStatus.OK


# ---------------------------------------------------------------------------
# ep-tamper-protection
# ---------------------------------------------------------------------------


def test_tamper_no_config_and_no_devices_is_gap() -> None:
    evidence = _demo()
    _bundle(evidence)["device_configurations"] = []
    _bundle(evidence)["tamper_device_state"] = {
        "sampled": 0,
        "enabled": 0,
        "disabled": 0,
        "unknown": 0,
        "unreadable": 0,
    }
    result = evaluate_endpoint_tamper_protection(_check("ep-tamper-protection"), evidence)
    assert result.status is FindingStatus.GAP


def test_tamper_unassigned_with_device_evidence_is_partial() -> None:
    evidence = _demo()
    for cfg in _bundle(evidence)["device_configurations"]:
        if cfg["id"] == "cfg-atp":
            cfg["assigned"] = False
            cfg["assignments"] = []
    result = evaluate_endpoint_tamper_protection(_check("ep-tamper-protection"), evidence)
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.GAP


def test_tamper_assigned_but_disabled_devices_is_partial() -> None:
    evidence = _demo()
    _bundle(evidence)["tamper_device_state"] = {
        "sampled": 2,
        "enabled": 1,
        "disabled": 1,
        "unknown": 0,
        "unreadable": 0,
    }
    result = evaluate_endpoint_tamper_protection(_check("ep-tamper-protection"), evidence)
    assert result.status is FindingStatus.PARTIAL
    assert "1 sampled device" in result.summary


def test_tamper_assigned_but_no_device_evidence_is_partial() -> None:
    evidence = _demo()
    _bundle(evidence)["tamper_device_state"] = {
        "sampled": 0,
        "enabled": 0,
        "disabled": 0,
        "unknown": 0,
        "unreadable": 0,
    }
    result = evaluate_endpoint_tamper_protection(_check("ep-tamper-protection"), evidence)
    assert result.status is FindingStatus.PARTIAL


def test_tamper_unknown_devices_keep_ok_with_limitation() -> None:
    evidence = _demo()
    _bundle(evidence)["tamper_device_state"] = {
        "sampled": 3,
        "enabled": 2,
        "disabled": 0,
        "unknown": 1,
        "unreadable": 1,
    }
    result = evaluate_endpoint_tamper_protection(_check("ep-tamper-protection"), evidence)
    assert result.status is FindingStatus.OK
    assert result.limitations


# ---------------------------------------------------------------------------
# ep-compliance-enforcement
# ---------------------------------------------------------------------------


def test_compliance_no_state_is_partial() -> None:
    evidence = _demo()
    _bundle(evidence)["compliance_state_summary"] = None
    result = evaluate_endpoint_compliance_enforcement(
        _check("ep-compliance-enforcement"), evidence
    )
    assert result.status is FindingStatus.PARTIAL


def test_compliance_no_managed_devices_is_partial() -> None:
    evidence = _demo()
    _bundle(evidence)["compliance_state_summary"] = {
        "compliantDeviceCount": 0,
        "nonCompliantDeviceCount": 0,
        "unknownDeviceCount": 0,
        "errorDeviceCount": 0,
        "conflictDeviceCount": 0,
        "inGracePeriodCount": 0,
    }
    result = evaluate_endpoint_compliance_enforcement(
        _check("ep-compliance-enforcement"), evidence
    )
    assert result.status is FindingStatus.PARTIAL


def test_compliance_all_noncompliant_is_gap() -> None:
    evidence = _demo()
    _bundle(evidence)["compliance_state_summary"] = {
        "compliantDeviceCount": 0,
        "nonCompliantDeviceCount": 12,
        "unknownDeviceCount": 0,
        "errorDeviceCount": 0,
        "conflictDeviceCount": 0,
        "inGracePeriodCount": 0,
    }
    result = evaluate_endpoint_compliance_enforcement(
        _check("ep-compliance-enforcement"), evidence
    )
    assert result.status is FindingStatus.GAP


def test_compliance_some_noncompliant_is_partial() -> None:
    evidence = _demo()
    _bundle(evidence)["compliance_state_summary"]["nonCompliantDeviceCount"] = 3
    result = evaluate_endpoint_compliance_enforcement(
        _check("ep-compliance-enforcement"), evidence
    )
    assert result.status is FindingStatus.PARTIAL


def test_compliance_surface_error_is_partial() -> None:
    evidence = _demo()
    _surface_error(evidence, "compliance_state_summary")
    result = evaluate_endpoint_compliance_enforcement(
        _check("ep-compliance-enforcement"), evidence
    )
    assert result.status is FindingStatus.PARTIAL


# ---------------------------------------------------------------------------
# ep-mam-app-protection
# ---------------------------------------------------------------------------


def test_mam_no_policies_is_gap() -> None:
    evidence = _demo()
    _bundle(evidence)["app_protection_policies"] = []
    result = evaluate_endpoint_mam_app_protection(_check("ep-mam-app-protection"), evidence)
    assert result.status is FindingStatus.GAP


def test_mam_unassigned_is_gap() -> None:
    evidence = _demo()
    for policy in _bundle(evidence)["app_protection_policies"]:
        policy["assigned"] = False
        policy["assignments"] = []
    result = evaluate_endpoint_mam_app_protection(_check("ep-mam-app-protection"), evidence)
    assert result.status is FindingStatus.GAP


def test_mam_unknown_assignment_mode_is_partial() -> None:
    evidence = _demo()
    _bundle(evidence)["app_protection_policies"] = [
        {
            "id": "mam-x",
            "displayName": "Mystery policy",
            "odata_type": "#microsoft.graph.managedAppProtection",
            "assignment_mode": "unknown",
            "assigned": False,
            "assignments": [],
            "assignments_error": False,
        }
    ]
    result = evaluate_endpoint_mam_app_protection(_check("ep-mam-app-protection"), evidence)
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.GAP


def test_mam_assignment_unreadable_is_partial() -> None:
    evidence = _demo()
    _bundle(evidence)["app_protection_policies"][0]["assignments_error"] = True
    result = evaluate_endpoint_mam_app_protection(_check("ep-mam-app-protection"), evidence)
    assert result.status is FindingStatus.PARTIAL


def test_mam_default_org_wide_policy_is_ok() -> None:
    evidence = _demo()
    _bundle(evidence)["app_protection_policies"] = [
        {
            "id": "mam-default",
            "displayName": "Org-wide default protection",
            "odata_type": "#microsoft.graph.defaultManagedAppProtection",
            "assignment_mode": "default",
            "assigned": True,
            "assignments": [],
            "assignments_error": False,
        }
    ]
    result = evaluate_endpoint_mam_app_protection(_check("ep-mam-app-protection"), evidence)
    assert result.status is FindingStatus.OK
    assert result.evidence["org_wide_count"] == 1


# ---------------------------------------------------------------------------
# Registry / licensing integration
# ---------------------------------------------------------------------------


def test_all_depth_checks_resolve_via_registry_direct() -> None:
    from licenselens.engine.registry import default_registry
    from licenselens.schema_contracts import EvaluationMode

    registry = default_registry()
    for check_id in _DEPTH_CHECKS:
        entry = registry.evaluator_for(check_id)
        assert entry.evaluation_mode is EvaluationMode.DIRECT, check_id


def test_entitlement_gate_prevents_unlicensed_depth_findings() -> None:
    checks = {check.id: check for check in load_checks()}
    for check_id in _DEPTH_CHECKS:
        finding = _evaluate_check(checks[check_id], set(), _demo())
        assert finding.status is FindingStatus.NOT_LICENSED, check_id


def test_dry_run_scan_renders_all_depth_checks_ok() -> None:
    auth = build_auth_context(mode=AuthMode.DRY_RUN, tenant_id="dry-run")
    result = run_scan(auth, dry_run=True)
    by_id = {finding.check_id: finding for finding in result.findings}
    for check_id in _DEPTH_CHECKS:
        assert check_id in by_id, check_id
        assert by_id[check_id].status is FindingStatus.OK, check_id


# ---------------------------------------------------------------------------
# Collector behavior
# ---------------------------------------------------------------------------


def _seed_full_bundle(fake: FakeGraphClient) -> None:
    fake.register_list(
        "/deviceManagement/managedDevices",
        ok(
            {
                "value": [
                    {"id": "d1", "operatingSystem": "Windows"},
                    {"id": "d2", "operatingSystem": "Windows"},
                    {"id": "d3", "operatingSystem": "iOS"},
                ]
            }
        ),
    )
    fake.register_get(
        "/deviceManagement/managedDevices/d1/windowsProtectionState",
        ok({"tamperProtectionEnabled": True}),
    )
    fake.register_get(
        "/deviceManagement/managedDevices/d2/windowsProtectionState",
        ok({"tamperProtectionEnabled": False}),
    )
    fake.register_list(
        "/deviceManagement/deviceCompliancePolicies",
        ok({"value": [{"id": "comp-1", "displayName": "Windows"}]}),
    )
    fake.register_list(
        "/deviceManagement/deviceCompliancePolicies/comp-1/assignments",
        ok({"value": [{"id": "a1"}]}),
    )
    fake.register_list(
        "/deviceManagement/deviceCompliancePolicies/comp-1/scheduledActionsForRule",
        ok({"value": []}),
    )
    fake.register_list(
        "/deviceManagement/configurationPolicies",
        ok(
            {
                "value": [
                    {
                        "id": "ep-asr",
                        "name": "Endpoint security - ASR",
                        "isAssigned": True,
                        "templateReference": {
                            "templateFamily": "endpointSecurityAttackSurfaceReduction"
                        },
                    }
                ]
            }
        ),
    )
    fake.register_list(
        "/deviceManagement/configurationPolicies/ep-asr/settings",
        ok(
            {
                "value": [
                    {
                        "settingInstance": {
                            "settingDefinitionId": (
                                "device_vendor_msft_policy_config_defender_"
                                "attacksurfacereductionrules"
                            ),
                            "groupSettingCollectionValue": [
                                {
                                    "children": [
                                        {
                                            "settingDefinitionId": (
                                                "device_vendor_msft_policy_config_defender_"
                                                "attacksurfacereductionrules_"
                                                "blockexecutionofpotentiallyobfuscatedscripts"
                                            )
                                        }
                                    ]
                                },
                                {
                                    "children": [
                                        {
                                            "settingDefinitionId": (
                                                "device_vendor_msft_policy_config_defender_"
                                                "attacksurfacereductionrules_"
                                                "blockcredentialstealing"
                                            )
                                        }
                                    ]
                                },
                            ]
                        }
                    }
                ]
            }
        ),
    )
    fake.register_list(
        "/deviceManagement/deviceConfigurations",
        ok(
            {
                "value": [
                    {
                        "id": "cfg-bl",
                        "displayName": "BitLocker encryption",
                        "@odata.type": "#microsoft.graph.windows10EndpointProtectionConfiguration",
                        "bitLockerEncryptDevice": True,
                    },
                    {
                        "id": "cfg-atp",
                        "displayName": "Defender ATP",
                        "@odata.type": (
                            "#microsoft.graph.windowsDefenderAdvancedThreatProtectionConfiguration"
                        ),
                    },
                ]
            }
        ),
    )
    fake.register_list(
        "/deviceManagement/deviceConfigurations/cfg-bl/assignments",
        ok({"value": [{"id": "ba1"}]}),
    )
    fake.register_list(
        "/deviceManagement/deviceConfigurations/cfg-atp/assignments",
        ok({"value": [{"id": "ba2"}]}),
    )
    fake.register_get(
        "/deviceManagement/advancedThreatProtectionOnboardingStateSummary",
        ok({"onboardedDeviceCount": 1}),
    )
    fake.register_list(
        "/deviceManagement/endpointSecurity/attackSurfaceReductionPolicies",
        error(404, "legacy ASR path unavailable"),
    )
    fake.register_get(
        "/deviceManagement/deviceCompliancePolicyDeviceStateSummary",
        ok({"compliantDeviceCount": 90, "nonCompliantDeviceCount": 0}),
    )
    fake.register_list(
        "/deviceAppManagement/managedAppProtections",
        ok(
            {
                "value": [
                    {
                        "id": "mam-ios",
                        "displayName": "iOS app protection",
                        "@odata.type": "#microsoft.graph.iosManagedAppProtection",
                    },
                    {
                        "id": "mam-default",
                        "displayName": "Default protection",
                        "@odata.type": "#microsoft.graph.defaultManagedAppProtection",
                    },
                ]
            }
        ),
    )
    fake.register_list(
        "/deviceAppManagement/iosManagedAppProtections/mam-ios/assignments",
        ok({"value": [{"id": "ma1"}]}),
    )


def test_collect_bundle_populates_all_depth_surfaces() -> None:
    fake = FakeGraphClient()
    _seed_full_bundle(fake)
    bundle = collect_intune_evidence_bundle(fake, licensed_units=100)

    assert bundle["errors"]["device_configurations"] == ""
    bitlocker = [c for c in bundle["device_configurations"] if c["id"] == "cfg-bl"][0]
    assert bitlocker["assigned"] is True
    assert bitlocker["bitLockerEncryptDevice"] is True

    assert bundle["errors"]["asr_policies"] == ""
    assert len(bundle["asr_policies"]) == 1
    asr = bundle["asr_policies"][0]
    assert asr["source"] == "configurationPolicies"
    assert asr["assigned"] is True
    assert asr["rule_count"] == 2
    assert asr["rules_error"] is False

    assert bundle["compliance_state_summary"]["compliantDeviceCount"] == 90
    assert bundle["errors"]["compliance_state_summary"] == ""

    mam = {p["id"]: p for p in bundle["app_protection_policies"]}
    assert mam["mam-ios"]["assigned"] is True
    assert mam["mam-ios"]["assignment_mode"] == "targeted"
    assert mam["mam-default"]["assigned"] is True
    assert mam["mam-default"]["assignment_mode"] == "default"

    assert bundle["tamper_device_state"] == {
        "sampled": 2,
        "enabled": 1,
        "disabled": 1,
        "unknown": 0,
        "unreadable": 0,
    }


def test_collect_bundle_asr_endpoint_security_path_is_preferred() -> None:
    fake = FakeGraphClient()
    _seed_full_bundle(fake)
    fake.register_list(
        "/deviceManagement/endpointSecurity/attackSurfaceReductionPolicies",
        ok({"value": [{"id": "asr-direct", "displayName": "ASR rules"}]}),
    )
    fake.register_list(
        "/deviceManagement/endpointSecurity/attackSurfaceReductionPolicies/asr-direct/assignments",
        ok({"value": [{"id": "aa1"}]}),
    )
    fake.register_list(
        "/deviceManagement/endpointSecurity/attackSurfaceReductionPolicies/asr-direct/settings",
        ok(
            {
                "value": [
                    {
                        "settingInstance": {
                            "settingDefinitionId": (
                                "device_vendor_msft_policy_config_defender_"
                                "attacksurfacereductionrules_blockabuseofexploitedvulnerable"
                            )
                        }
                    }
                ]
            }
        ),
    )
    bundle = collect_intune_evidence_bundle(fake)
    asr = bundle["asr_policies"][0]
    assert asr["source"] == "endpointSecurity"
    assert asr["assigned"] is True
    assert asr["rule_count"] == 1


def test_collect_bundle_mam_assignment_denied_is_flagged() -> None:
    fake = FakeGraphClient()
    _seed_full_bundle(fake)
    fake.register_list(
        "/deviceAppManagement/iosManagedAppProtections/mam-ios/assignments",
        error(403, "Forbidden"),
    )
    bundle = collect_intune_evidence_bundle(fake)
    mam = {p["id"]: p for p in bundle["app_protection_policies"]}
    assert mam["mam-ios"]["assignments_error"] is True
    assert mam["mam-ios"]["assigned"] is False


def test_collect_bundle_unsupported_china_covers_depth_surfaces() -> None:
    fake = FakeGraphClient(cloud=CloudEnvironment.CHINA)
    bundle = collect_intune_evidence_bundle(fake)
    for surface in (
        "device_configurations",
        "asr_policies",
        "compliance_state_summary",
        "app_protection_policies",
    ):
        assert bundle["errors"][surface] != "", surface
    assert bundle["tamper_device_state"]["sampled"] == 0
