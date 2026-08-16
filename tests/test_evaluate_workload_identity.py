"""Unit tests for the t12 identity checks (workload CA, break-glass, access packages)."""

from licenselens.engine.evaluate import (
    evaluate_break_glass_exclusion,
    evaluate_ca_workload_identity,
    evaluate_entitlement_access_packages,
)
from licenselens.models import CheckDefinition, FindingStatus, Workload

GA = "62e90394-69f5-4237-9190-012177145e10"


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=Workload.IDENTITY)


# -- id-ca-workload-identity -------------------------------------------------


def _workload_risk_policy(state: str = "enabled") -> dict:
    return {
        "id": "sp-risk-policy",
        "displayName": "Workload identity risk",
        "state": state,
        "conditions": {
            "users": {"includeUsers": ["None"]},
            "clientApplications": {"includeServicePrincipals": ["All"]},
            "servicePrincipalRiskLevels": ["medium", "high"],
        },
        "grantControls": {"operator": "AND", "builtInControls": ["mfa"]},
    }


def test_ca_workload_identity_ok_when_enforced_policy_targets_sp_risk():
    result = evaluate_ca_workload_identity(
        _check("id-ca-workload-identity"),
        {"ca_policies": [_workload_risk_policy("enabled")]},
    )
    assert result.status == FindingStatus.OK
    assert result.evidence["risk_levels_covered"] == ["high", "medium"]


def test_ca_workload_identity_gap_when_no_policy_targets_sp_risk():
    policies = [
        {
            "id": "mfa-all",
            "displayName": "MFA all users",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "clientAppTypes": ["all"],
            },
            "grantControls": {"builtInControls": ["mfa"]},
        }
    ]
    result = evaluate_ca_workload_identity(
        _check("id-ca-workload-identity"),
        {"ca_policies": policies},
    )
    assert result.status == FindingStatus.GAP
    assert result.evidence["enforced_workload_risk_policies"] == []


def test_ca_workload_identity_gap_when_report_only():
    result = evaluate_ca_workload_identity(
        _check("id-ca-workload-identity"),
        {"ca_policies": [_workload_risk_policy("enabledForReportingButNotEnforced")]},
    )
    assert result.status == FindingStatus.GAP
    assert result.evidence["report_only_workload_risk_policies"] == ["Workload identity risk"]


def test_ca_workload_identity_gap_when_sp_targeting_has_no_risk_conditions():
    policy = _workload_risk_policy("enabled")
    policy["conditions"]["servicePrincipalRiskLevels"] = []
    result = evaluate_ca_workload_identity(
        _check("id-ca-workload-identity"),
        {"ca_policies": [policy]},
    )
    assert result.status == FindingStatus.GAP
    assert result.evidence["service_principal_targeting_policies"] == ["Workload identity risk"]


# -- id-break-glass-exclusion -------------------------------------------------


def _ga_assignment(principal_id: str) -> dict:
    return {
        "id": f"asg-{principal_id}",
        "principalId": principal_id,
        "roleDefinitionId": GA,
        "directoryScopeId": "/",
    }


def test_break_glass_ok_when_account_identified_and_exclusions_justified():
    evidence = {
        "role_assignments": [_ga_assignment("bg-user-1")],
        "role_eligibilities": [],
        "ca_policies": [
            {
                "id": "mfa-all",
                "displayName": "MFA all",
                "state": "enabled",
                "conditions": {
                    "users": {
                        "includeUsers": ["All"],
                        "excludeUsers": ["bg-user-1"],
                    }
                },
                "grantControls": {"builtInControls": ["mfa"]},
            }
        ],
        "break_glass_principal_ids": ["bg-user-1"],
    }
    result = evaluate_break_glass_exclusion(_check("id-break-glass-exclusion"), evidence)
    assert result.status == FindingStatus.OK
    assert result.evidence["identified_break_glass_accounts"] == ["bg-user-1"]


def test_break_glass_gap_when_no_ga_account_and_nothing_declared():
    evidence = {
        "role_assignments": [],
        "role_eligibilities": [],
        "ca_policies": [],
        "break_glass_principal_ids": [],
    }
    result = evaluate_break_glass_exclusion(_check("id-break-glass-exclusion"), evidence)
    assert result.status == FindingStatus.GAP
    assert "break-glass account could be identified" in result.summary


def test_break_glass_partial_when_declared_principal_not_found():
    evidence = {
        "role_assignments": [_ga_assignment("admin-1")],
        "role_eligibilities": [],
        "ca_policies": [],
        "break_glass_principal_ids": ["missing-bg-user"],
    }
    result = evaluate_break_glass_exclusion(_check("id-break-glass-exclusion"), evidence)
    assert result.status == FindingStatus.PARTIAL
    assert "did not match any scanned Global Administrator" in result.summary


def test_break_glass_partial_when_unjustified_exclusions_remain():
    evidence = {
        "role_assignments": [_ga_assignment("bg-user-1"), _ga_assignment("admin-2")],
        "role_eligibilities": [],
        "ca_policies": [
            {
                "id": "mfa-all",
                "displayName": "MFA all",
                "state": "enabled",
                "conditions": {
                    "users": {
                        "includeUsers": ["All"],
                        "excludeUsers": ["bg-user-1", "admin-2"],
                    }
                },
                "grantControls": {"builtInControls": ["mfa"]},
            }
        ],
        "break_glass_principal_ids": ["bg-user-1"],
    }
    result = evaluate_break_glass_exclusion(_check("id-break-glass-exclusion"), evidence)
    assert result.status == FindingStatus.PARTIAL
    assert result.evidence["unjustified_exclusion_count"] == 1
    assert result.evidence["global_admin_exclusion_issues"]


# -- id-entitlement-access-packages ------------------------------------------


def _visible_access_package() -> dict:
    return {
        "id": "ap-1",
        "displayName": "Contractor access",
        "description": "Baseline contractor bundle",
        "isHidden": False,
        "catalogId": "catalog-1",
    }


def test_entitlement_access_packages_ok_when_visible_package_exists():
    result = evaluate_entitlement_access_packages(
        _check("id-entitlement-access-packages"),
        {"access_packages": [_visible_access_package()]},
    )
    assert result.status == FindingStatus.OK
    assert result.evidence["access_package_count"] == 1


def test_entitlement_access_packages_gap_when_no_packages():
    result = evaluate_entitlement_access_packages(
        _check("id-entitlement-access-packages"),
        {"access_packages": []},
    )
    assert result.status == FindingStatus.GAP


def test_entitlement_access_packages_partial_when_all_hidden():
    hidden = _visible_access_package()
    hidden["isHidden"] = True
    result = evaluate_entitlement_access_packages(
        _check("id-entitlement-access-packages"),
        {"access_packages": [hidden]},
    )
    assert result.status == FindingStatus.PARTIAL


def test_entitlement_access_packages_error_when_collection_failed():
    result = evaluate_entitlement_access_packages(
        _check("id-entitlement-access-packages"),
        {"access_packages_error": "EntitlementManagement.Read.All denied"},
    )
    assert result.status == FindingStatus.ERROR
