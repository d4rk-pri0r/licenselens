from licenselens.collectors.conditional_access import DEMO_CA_POLICIES
from licenselens.engine.evaluate import evaluate_ca_priv_gaps, evaluate_idprotect_off
from licenselens.models import CheckDefinition, FindingStatus, Workload


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(
        id=check_id,
        title=check_id,
        workload=Workload.IDENTITY,
    )


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
    result = evaluate_idprotect_off(
        _check("id-idprotect-off"), {"ca_policies": DEMO_CA_POLICIES}
    )
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
