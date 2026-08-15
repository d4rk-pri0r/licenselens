"""Wave 3 endpoint/XDR evaluator coverage (Todo 22)."""

from __future__ import annotations

import copy
from typing import Any

from licenselens.collectors.contracts import CloudEnvironment
from licenselens.collectors.intune_policy import (
    DEMO_INTUNE_EVIDENCE_BUNDLE,
    collect_intune_evidence_bundle,
    intune_licensed_units,
)
from licenselens.collectors.skus import demo_skus
from licenselens.engine.loader import load_checks
from licenselens.engine.runner import _evaluate_check
from licenselens.evaluators.endpoint_intune import (
    evaluate_endpoint_compliance_noncompliance_action,
    evaluate_endpoint_compliance_policy_assigned,
    evaluate_endpoint_enrollment_coverage,
)
from licenselens.evaluators.endpoint_intune_policy import (
    evaluate_endpoint_mde_connector,
    evaluate_endpoint_security_baseline,
    evaluate_endpoint_security_policy_coverage,
)
from licenselens.evaluators.endpoint_mde_xdr import (
    evaluate_mde_sensor_health,
    evaluate_xdr_incident_readiness,
)
from licenselens.models import CheckDefinition, FindingStatus, Workload
from tests.fake_clients import FakeGraphClient, error, ok

_ENDPOINT_CHECKS = (
    "endpoint-enrollment-coverage",
    "endpoint-compliance-policy-assigned",
    "endpoint-compliance-noncompliance-action",
    "endpoint-security-baseline",
    "endpoint-security-policy-coverage",
    "endpoint-mde-connector",
    "mde-sensor-health",
    "xdr-incident-readiness",
)


def _check(check_id: str) -> CheckDefinition:
    workload = Workload.DEFENDER if check_id == "xdr-incident-readiness" else Workload.ENDPOINT
    return CheckDefinition(id=check_id, title=check_id, workload=workload)


def _demo() -> dict[str, Any]:
    return {"intune_bundle": copy.deepcopy(DEMO_INTUNE_EVIDENCE_BUNDLE)}


def _bundle(evidence: dict[str, Any]) -> dict[str, Any]:
    return evidence["intune_bundle"]


def test_demo_endpoint_matrix_produces_defined_statuses() -> None:
    evidence = _demo()
    assert (
        evaluate_endpoint_compliance_policy_assigned(
            _check("endpoint-compliance-policy-assigned"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_endpoint_compliance_noncompliance_action(
            _check("endpoint-compliance-noncompliance-action"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_endpoint_security_baseline(_check("endpoint-security-baseline"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_endpoint_security_policy_coverage(
            _check("endpoint-security-policy-coverage"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_endpoint_mde_connector(_check("endpoint-mde-connector"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_endpoint_enrollment_coverage(
            _check("endpoint-enrollment-coverage"), evidence
        ).status
        is FindingStatus.GAP
    )


def test_enrollment_zero_devices_is_gap() -> None:
    evidence = _demo()
    _bundle(evidence)["managed_devices"] = []
    result = evaluate_endpoint_enrollment_coverage(_check("endpoint-enrollment-coverage"), evidence)
    assert result.status is FindingStatus.GAP


def test_enrollment_without_licensed_units_is_partial() -> None:
    evidence = _demo()
    _bundle(evidence)["licensed_units"] = None
    result = evaluate_endpoint_enrollment_coverage(_check("endpoint-enrollment-coverage"), evidence)
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.GAP


def test_compliance_no_policies_is_gap() -> None:
    evidence = _demo()
    _bundle(evidence)["compliance_policies"] = []
    result = evaluate_endpoint_compliance_policy_assigned(
        _check("endpoint-compliance-policy-assigned"), evidence
    )
    assert result.status is FindingStatus.GAP


def test_compliance_unassigned_policy_is_gap() -> None:
    evidence = _demo()
    for policy in _bundle(evidence)["compliance_policies"]:
        policy["assigned"] = False
        policy["assignments"] = []
    result = evaluate_endpoint_compliance_policy_assigned(
        _check("endpoint-compliance-policy-assigned"), evidence
    )
    assert result.status is FindingStatus.GAP


def test_compliance_assignment_unreadable_is_partial_not_gap() -> None:
    evidence = _demo()
    _bundle(evidence)["compliance_policies"][0]["assignments_error"] = True
    result = evaluate_endpoint_compliance_policy_assigned(
        _check("endpoint-compliance-policy-assigned"), evidence
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.GAP


def test_compliance_uncovered_platform_is_partial() -> None:
    evidence = _demo()
    _bundle(evidence)["managed_devices"].append({"id": "dev-3", "operatingSystem": "Android"})
    result = evaluate_endpoint_compliance_policy_assigned(
        _check("endpoint-compliance-policy-assigned"), evidence
    )
    assert result.status is FindingStatus.PARTIAL
    assert "Android" in result.evidence["uncovered_platforms"]


def test_noncompliance_no_action_is_gap() -> None:
    evidence = _demo()
    for policy in _bundle(evidence)["compliance_policies"]:
        policy["has_noncompliance_action"] = False
        policy["noncompliance_actions"] = []
    result = evaluate_endpoint_compliance_noncompliance_action(
        _check("endpoint-compliance-noncompliance-action"), evidence
    )
    assert result.status is FindingStatus.GAP


def test_noncompliance_action_unreadable_is_partial() -> None:
    evidence = _demo()
    _bundle(evidence)["compliance_policies"][0]["noncompliance_actions_error"] = True
    result = evaluate_endpoint_compliance_noncompliance_action(
        _check("endpoint-compliance-noncompliance-action"), evidence
    )
    assert result.status is FindingStatus.PARTIAL


def test_baseline_missing_is_gap() -> None:
    evidence = _demo()
    _bundle(evidence)["configuration_policies"] = [
        p
        for p in _bundle(evidence)["configuration_policies"]
        if "baseline" not in str(p.get("templateReference", {}).get("templateFamily", "")).lower()
    ]
    result = evaluate_endpoint_security_baseline(_check("endpoint-security-baseline"), evidence)
    assert result.status is FindingStatus.GAP


def test_policy_coverage_missing_family_is_partial() -> None:
    evidence = _demo()
    _bundle(evidence)["configuration_policies"] = [
        p
        for p in _bundle(evidence)["configuration_policies"]
        if "attacksurfacereduction"
        not in str(p.get("templateReference", {}).get("templateFamily", "")).lower()
    ]
    result = evaluate_endpoint_security_policy_coverage(
        _check("endpoint-security-policy-coverage"), evidence
    )
    assert result.status is FindingStatus.PARTIAL
    assert "attack surface reduction" not in result.evidence["covered_families"]


def test_policy_coverage_none_is_gap() -> None:
    evidence = _demo()
    _bundle(evidence)["configuration_policies"] = []
    result = evaluate_endpoint_security_policy_coverage(
        _check("endpoint-security-policy-coverage"), evidence
    )
    assert result.status is FindingStatus.GAP


def test_mde_connector_atp_missing_is_partial() -> None:
    evidence = _demo()
    _bundle(evidence)["atp_onboarding_state"] = None
    result = evaluate_endpoint_mde_connector(_check("endpoint-mde-connector"), evidence)
    assert result.status is FindingStatus.PARTIAL


def test_mde_connector_no_onboarded_is_gap() -> None:
    evidence = _demo()
    _bundle(evidence)["atp_onboarding_state"] = {
        "onboardedDeviceCount": 0,
        "unknownDeviceCount": 5,
        "unhealthyDeviceCount": 0,
    }
    result = evaluate_endpoint_mde_connector(_check("endpoint-mde-connector"), evidence)
    assert result.status is FindingStatus.GAP


def test_mde_sensor_health_all_active_is_ok() -> None:
    result = evaluate_mde_sensor_health(
        _check("mde-sensor-health"),
        {
            "mde_health": {
                "machines_sampled": 10,
                "active_healthy": 10,
                "impaired_communication": 0,
                "no_sensor_data": 0,
                "truncated": False,
            }
        },
    )
    assert result.status is FindingStatus.OK


def test_mde_sensor_health_unhealthy_is_gap() -> None:
    result = evaluate_mde_sensor_health(
        _check("mde-sensor-health"),
        {
            "mde_health": {
                "machines_sampled": 10,
                "active_healthy": 3,
                "impaired_communication": 4,
                "no_sensor_data": 3,
                "truncated": False,
            }
        },
    )
    assert result.status is FindingStatus.GAP


def test_mde_sensor_health_inactive_sensors_are_not_ok() -> None:
    result = evaluate_mde_sensor_health(
        _check("mde-sensor-health"),
        {
            "mde_health": {
                "machines_sampled": 10,
                "active_healthy": 6,
                "impaired_communication": 0,
                "no_sensor_data": 0,
                "inactive": 4,
                "truncated": False,
            }
        },
    )
    assert result.status is FindingStatus.GAP


def test_mde_sensor_health_empty_is_partial() -> None:
    result = evaluate_mde_sensor_health(
        _check("mde-sensor-health"), {"mde_health": {"machines_sampled": 0}}
    )
    assert result.status is FindingStatus.PARTIAL


def test_xdr_incidents_present_is_ok() -> None:
    result = evaluate_xdr_incident_readiness(
        _check("xdr-incident-readiness"),
        {"security_alerts_bundle": {"incident_count": 3, "alert_count": 0}},
    )
    assert result.status is FindingStatus.OK


def test_xdr_empty_incidents_is_partial_never_gap() -> None:
    result = evaluate_xdr_incident_readiness(
        _check("xdr-incident-readiness"),
        {"security_alerts_bundle": {"incident_count": 0, "alert_count": 0}},
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.GAP
    assert result.status is not FindingStatus.OK


def test_intune_surface_unreadable_is_partial_not_gap() -> None:
    evidence = _demo()
    _bundle(evidence)["errors"]["compliance_policies"] = "403 Forbidden"
    result = evaluate_endpoint_compliance_policy_assigned(
        _check("endpoint-compliance-policy-assigned"), evidence
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.GAP


def test_malformed_intune_bundle_is_partial_not_ok() -> None:
    result = evaluate_endpoint_compliance_policy_assigned(
        _check("endpoint-compliance-policy-assigned"), {"intune_bundle": "not-a-dict"}
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.OK


def test_malformed_mde_health_is_partial_not_ok() -> None:
    result = evaluate_mde_sensor_health(
        _check("mde-sensor-health"), {"mde_health": {"machines_sampled": "nope"}}
    )
    assert result.status is FindingStatus.PARTIAL


def test_intune_licensed_units_from_demo_skus() -> None:
    assert intune_licensed_units(demo_skus()) == 100


def test_intune_licensed_units_none_without_intune() -> None:
    from licenselens.models import SubscribedSku

    assert (
        intune_licensed_units([SubscribedSku(sku_part_number="O365_BUSINESS", service_plans=[])])
        is None
    )


def test_collect_intune_bundle_enriches_assignments() -> None:
    fake = FakeGraphClient()
    fake.register_list(
        "/deviceManagement/deviceCompliancePolicies",
        ok({"value": [{"id": "comp-1", "displayName": "Windows", "platforms": "windows10"}]}),
    )
    fake.register_list(
        "/deviceManagement/deviceCompliancePolicies/comp-1/assignments",
        ok({"value": [{"id": "a1"}]}),
    )
    fake.register_list(
        "/deviceManagement/deviceCompliancePolicies/comp-1/scheduledActionsForRule",
        ok({"value": [{"id": "sar1"}]}),
    )
    fake.register_list("/deviceManagement/configurationPolicies", ok({"value": []}))
    fake.register_list("/deviceManagement/managedDevices", ok({"value": []}))
    fake.register_get(
        "/deviceManagement/advancedThreatProtectionOnboardingStateSummary",
        ok({"onboardedDeviceCount": 0, "unknownDeviceCount": 0}),
    )

    bundle = collect_intune_evidence_bundle(fake, licensed_units=10)
    assert bundle["errors"]["compliance_policies"] == ""
    policy = bundle["compliance_policies"][0]
    assert policy["assigned"] is True
    assert policy["has_noncompliance_action"] is True
    assert bundle["licensed_units"] == 10


def test_collect_intune_bundle_assignment_denied_is_flagged() -> None:
    fake = FakeGraphClient()
    fake.register_list(
        "/deviceManagement/deviceCompliancePolicies",
        ok({"value": [{"id": "comp-1", "displayName": "Windows"}]}),
    )
    fake.register_list(
        "/deviceManagement/deviceCompliancePolicies/comp-1/assignments",
        error(403, "Forbidden"),
    )
    fake.register_list(
        "/deviceManagement/deviceCompliancePolicies/comp-1/scheduledActionsForRule",
        ok({"value": []}),
    )
    fake.register_list("/deviceManagement/configurationPolicies", ok({"value": []}))
    fake.register_list("/deviceManagement/managedDevices", ok({"value": []}))
    fake.register_get(
        "/deviceManagement/advancedThreatProtectionOnboardingStateSummary",
        ok({"onboardedDeviceCount": 0}),
    )

    bundle = collect_intune_evidence_bundle(fake)
    policy = bundle["compliance_policies"][0]
    assert policy["assignments_error"] is True
    assert policy["assigned"] is False


def test_collect_intune_bundle_unsupported_china() -> None:
    fake = FakeGraphClient(cloud=CloudEnvironment.CHINA)
    bundle = collect_intune_evidence_bundle(fake)
    assert bundle["errors"]["compliance_policies"] != ""
    assert bundle["errors"]["managed_devices"] != ""


def test_all_endpoint_checks_resolve_via_registry_direct() -> None:
    from licenselens.engine.registry import default_registry
    from licenselens.schema_contracts import EvaluationMode

    registry = default_registry()
    for check_id in _ENDPOINT_CHECKS:
        entry = registry.evaluator_for(check_id)
        assert entry.evaluation_mode is EvaluationMode.DIRECT, check_id


def test_entitlement_gate_prevents_irrelevant_endpoint_findings() -> None:
    checks = {check.id: check for check in load_checks()}
    for check_id in _ENDPOINT_CHECKS:
        check = checks[check_id]
        finding = _evaluate_check(check, set(), _demo())
        assert finding.status is FindingStatus.NOT_LICENSED, check_id
