from licenselens.collectors.conditional_access import DEMO_CA_POLICIES
from licenselens.collectors.privileged_roles import DEMO_ROLE_ASSIGNMENTS
from licenselens.engine.evaluate import (
    evaluate_ca_priv_gaps,
    evaluate_idprotect_off,
    evaluate_pim_unused,
)
from licenselens.models import CheckDefinition, ExposureClass, FindingStatus, Workload


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(
        id=check_id,
        title=check_id,
        workload=Workload.IDENTITY,
    )


def _policies(*policies: dict) -> list[dict]:
    return list(policies)


def test_ca_priv_gaps_demo_is_partial():
    result = evaluate_ca_priv_gaps(_check("id-ca-priv-gaps"), {"ca_policies": DEMO_CA_POLICIES})
    assert result.status == FindingStatus.PARTIAL
    assert result.evidence["mfa_enforced_policies"]
    assert result.evidence["legacy_block_report_only"]


def test_ca_priv_gaps_ok_when_mfa_and_legacy_enforced():
    policies = [
        {
            "displayName": "MFA all",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "clientAppTypes": ["all"],
            },
            "grantControls": {"builtInControls": ["mfa"]},
        },
        {
            "displayName": "Block legacy",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "clientAppTypes": ["exchangeActiveSync", "other"],
            },
            "grantControls": {"builtInControls": ["block"]},
        },
    ]
    result = evaluate_ca_priv_gaps(_check("id-ca-priv-gaps"), {"ca_policies": policies})
    assert result.status == FindingStatus.OK


def test_ca_priv_gaps_empty_is_gap():
    result = evaluate_ca_priv_gaps(_check("id-ca-priv-gaps"), {"ca_policies": []})
    assert result.status == FindingStatus.GAP


def test_idprotect_demo_is_gap():
    result = evaluate_idprotect_off(_check("id-idprotect-off"), {"ca_policies": DEMO_CA_POLICIES})
    assert result.status == FindingStatus.GAP


def test_idprotect_ok_with_both_risk_policies():
    policies = [
        {
            "displayName": "Sign-in risk",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "signInRiskLevels": ["high", "medium"],
                "userRiskLevels": [],
            },
            "grantControls": {"builtInControls": ["mfa"]},
        },
        {
            "displayName": "User risk",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "signInRiskLevels": [],
                "userRiskLevels": ["high"],
            },
            "grantControls": {"builtInControls": ["passwordChange"]},
        },
    ]
    result = evaluate_idprotect_off(_check("id-idprotect-off"), {"ca_policies": policies})
    assert result.status == FindingStatus.OK


def test_idprotect_partial_report_only():
    policies = [
        {
            "displayName": "Sign-in risk RO",
            "state": "enabledForReportingButNotEnforced",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "signInRiskLevels": ["high"],
                "userRiskLevels": [],
            },
            "grantControls": {"builtInControls": ["mfa"]},
        },
    ]
    result = evaluate_idprotect_off(_check("id-idprotect-off"), {"ca_policies": policies})
    assert result.status == FindingStatus.PARTIAL


_MFA_ALL = {
    "displayName": "MFA all",
    "state": "enabled",
    "conditions": {
        "users": {"includeUsers": ["All"], "includeRoles": []},
        "clientAppTypes": ["all"],
    },
    "grantControls": {"builtInControls": ["mfa"]},
}
_LEGACY_BLOCK = {
    "displayName": "Block legacy",
    "state": "enabled",
    "conditions": {
        "users": {"includeUsers": ["All"], "includeRoles": []},
        "clientAppTypes": ["exchangeActiveSync", "other"],
    },
    "grantControls": {"builtInControls": ["block"]},
}
_LEGACY_REPORT = {
    "displayName": "Block legacy (report)",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
        "users": {"includeUsers": ["All"], "includeRoles": []},
        "clientAppTypes": ["exchangeActiveSync", "other"],
    },
    "grantControls": {"builtInControls": ["block"]},
}
_MFA_PRIV_ROLES = {
    "displayName": "MFA privileged",
    "state": "enabled",
    "conditions": {
        "users": {"includeUsers": [], "includeRoles": ["62e90394-69f5-4237-9190-012177145e10"]},
        "clientAppTypes": ["all"],
    },
    "grantControls": {"builtInControls": ["mfa"]},
}


def _ga_assignments() -> list[dict]:
    return [a for a in DEMO_ROLE_ASSIGNMENTS if a.get("principalId") == "user-admin-1"]


def test_legacy_auth_open_is_exposed():
    result = evaluate_ca_priv_gaps(
        _check("id-ca-priv-gaps"),
        {"ca_policies": _policies(_MFA_ALL), "role_assignments": []},
    )
    assert result.exposure_class == ExposureClass.EXPOSED
    assert "legacy_auth_broadly_allowed" in result.evidence["exposure_flags"]
    assert "EXPOSED" in (result.customer_summary or "")


def test_legacy_report_only_is_not_exposed():
    result = evaluate_ca_priv_gaps(
        _check("id-ca-priv-gaps"),
        {"ca_policies": _policies(_MFA_ALL, _LEGACY_REPORT), "role_assignments": []},
    )
    assert result.exposure_class == ExposureClass.NONE
    assert result.status == FindingStatus.PARTIAL
    assert "legacy_auth_broadly_allowed" not in result.evidence["exposure_flags"]


def test_mfa_less_global_admin_is_exposed():
    result = evaluate_ca_priv_gaps(
        _check("id-ca-priv-gaps"),
        {"ca_policies": _policies(_LEGACY_BLOCK), "role_assignments": _ga_assignments()},
    )
    assert result.exposure_class == ExposureClass.EXPOSED
    assert "mfa_missing_for_privileged" in result.evidence["exposure_flags"]
    assert result.evidence["global_admin_standing_count"] >= 1
    # Break-glass caveat must be recorded.
    assert any("Break-glass" in lim for lim in result.limitations)


def test_mfa_enforced_for_privileged_roles_is_not_exposed():
    result = evaluate_ca_priv_gaps(
        _check("id-ca-priv-gaps"),
        {
            "ca_policies": _policies(_MFA_PRIV_ROLES, _LEGACY_BLOCK),
            "role_assignments": _ga_assignments(),
        },
    )
    assert result.exposure_class == ExposureClass.NONE
    assert "mfa_missing_for_privileged" not in result.evidence["exposure_flags"]


def test_no_privileged_principals_means_no_mfa_exposure():
    result = evaluate_ca_priv_gaps(
        _check("id-ca-priv-gaps"),
        {"ca_policies": _policies(_LEGACY_BLOCK), "role_assignments": []},
    )
    assert result.exposure_class == ExposureClass.NONE


def test_demo_tenant_is_not_exposed():
    # Demo fixture: MFA enforced + legacy report-only -> partial, not exposed.
    result = evaluate_ca_priv_gaps(
        _check("id-ca-priv-gaps"),
        {"ca_policies": DEMO_CA_POLICIES, "role_assignments": DEMO_ROLE_ASSIGNMENTS},
    )
    assert result.status == FindingStatus.PARTIAL
    assert result.exposure_class == ExposureClass.NONE


def test_pim_unused_remains_non_exposed_ordinary_gap():
    # PIM unused must never be promoted to an exposure class.
    result = evaluate_pim_unused(
        _check("id-pim-unused"),
        {"role_assignments": DEMO_ROLE_ASSIGNMENTS, "role_eligibilities": []},
    )
    assert result.exposure_class == ExposureClass.NONE
    assert result.status == FindingStatus.GAP
