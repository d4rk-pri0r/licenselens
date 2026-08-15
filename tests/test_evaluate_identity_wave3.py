"""Wave 3 Entra/identity check family evaluator coverage."""

from __future__ import annotations

from licenselens.engine.evaluate import (
    evaluate_app_registration_admin_only,
    evaluate_app_risky_delegated_consent,
    evaluate_auth_methods_migration,
    evaluate_auth_weak_methods_disabled,
    evaluate_ca_device_code_block,
    evaluate_ca_high_risk_users,
    evaluate_ca_legacy_auth_block,
    evaluate_ca_mfa_all_users,
    evaluate_ca_phishing_resistant_privileged,
    evaluate_ga_count_bounds,
    evaluate_guest_directory_access_limited,
    evaluate_password_never_expire,
    evaluate_pim_no_permanent_privileged,
)
from licenselens.models import CheckDefinition, FindingStatus, Workload

GA = "62e90394-69f5-4237-9190-012177145e10"


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=Workload.IDENTITY)


def test_legacy_auth_gap_when_missing() -> None:
    result = evaluate_ca_legacy_auth_block(_check("id-ca-legacy-auth-block"), {"ca_policies": []})
    assert result.status == FindingStatus.GAP


def test_legacy_auth_ok_when_enforced() -> None:
    policies = [
        {
            "displayName": "Block legacy",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"], "excludeUsers": []},
                "clientAppTypes": ["exchangeActiveSync", "other"],
            },
            "grantControls": {"builtInControls": ["block"]},
        }
    ]
    result = evaluate_ca_legacy_auth_block(
        _check("id-ca-legacy-auth-block"),
        {"ca_policies": policies, "break_glass_principal_ids": []},
    )
    assert result.status == FindingStatus.OK


def test_legacy_auth_partial_report_only() -> None:
    policies = [
        {
            "displayName": "Block legacy RO",
            "state": "enabledForReportingButNotEnforced",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "clientAppTypes": ["exchangeActiveSync", "other"],
            },
            "grantControls": {"builtInControls": ["block"]},
        }
    ]
    result = evaluate_ca_legacy_auth_block(
        _check("id-ca-legacy-auth-block"),
        {"ca_policies": policies},
    )
    assert result.status == FindingStatus.PARTIAL


def test_mfa_all_users_unjustified_exclusion_is_partial() -> None:
    policies = [
        {
            "displayName": "MFA all",
            "state": "enabled",
            "conditions": {
                "users": {
                    "includeUsers": ["All"],
                    "excludeUsers": ["mystery-user"],
                },
                "clientAppTypes": ["all"],
            },
            "grantControls": {"builtInControls": ["mfa"]},
        }
    ]
    result = evaluate_ca_mfa_all_users(
        _check("id-ca-mfa-all-users"),
        {"ca_policies": policies, "break_glass_principal_ids": []},
    )
    assert result.status == FindingStatus.PARTIAL
    assert result.evidence["unjustified_exclusion_issues"]


def test_mfa_all_users_named_break_glass_ok() -> None:
    policies = [
        {
            "displayName": "MFA all",
            "state": "enabled",
            "conditions": {
                "users": {
                    "includeUsers": ["All"],
                    "excludeUsers": ["break-glass-1"],
                },
                "clientAppTypes": ["all"],
            },
            "grantControls": {"builtInControls": ["mfa"]},
        }
    ]
    result = evaluate_ca_mfa_all_users(
        _check("id-ca-mfa-all-users"),
        {
            "ca_policies": policies,
            "break_glass_principal_ids": ["break-glass-1"],
        },
    )
    assert result.status == FindingStatus.OK


def test_high_risk_users_ok() -> None:
    policies = [
        {
            "displayName": "Block high user risk",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "userRiskLevels": ["high"],
            },
            "grantControls": {"builtInControls": ["block"]},
        }
    ]
    result = evaluate_ca_high_risk_users(
        _check("id-ca-high-risk-users"),
        {"ca_policies": policies},
    )
    assert result.status == FindingStatus.OK


def test_phishing_resistant_privileged_ok() -> None:
    policies = [
        {
            "displayName": "PR MFA admins",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": [], "includeRoles": [GA]},
            },
            "grantControls": {
                "authenticationStrength": {
                    "id": "00000000-0000-0000-0000-000000000003",
                    "displayName": "Phishing-resistant MFA",
                }
            },
        }
    ]
    result = evaluate_ca_phishing_resistant_privileged(
        _check("id-ca-phishing-resistant-privileged"),
        {"ca_policies": policies},
    )
    assert result.status == FindingStatus.OK


def test_device_code_block_gap() -> None:
    result = evaluate_ca_device_code_block(
        _check("id-ca-device-code-block"),
        {"ca_policies": []},
    )
    assert result.status == FindingStatus.GAP


def test_auth_migration_complete_ok() -> None:
    result = evaluate_auth_methods_migration(
        _check("id-auth-methods-migration"),
        {"auth_methods_bundle": {"policy": {"policyMigrationState": "migrationComplete"}}},
    )
    assert result.status == FindingStatus.OK


def test_auth_weak_methods_gap() -> None:
    result = evaluate_auth_weak_methods_disabled(
        _check("id-auth-weak-methods-disabled"),
        {
            "auth_methods_bundle": {
                "configurations": [
                    {"id": "sms", "state": "enabled"},
                    {"id": "fido2", "state": "enabled"},
                ]
            }
        },
    )
    assert result.status == FindingStatus.GAP
    assert "sms" in result.evidence["enabled_weak_methods"]


def test_app_registration_admin_only_gap() -> None:
    result = evaluate_app_registration_admin_only(
        _check("id-app-registration-admin-only"),
        {"authorization_policy": {"defaultUserRolePermissions": {"allowedToCreateApps": True}}},
    )
    assert result.status == FindingStatus.GAP


def test_app_risky_consent_gap() -> None:
    result = evaluate_app_risky_delegated_consent(
        _check("id-app-risky-delegated-consent"),
        {
            "applications_bundle": {
                "oauth2_permission_grants": [
                    {
                        "clientId": "sp-1",
                        "consentType": "AllPrincipals",
                        "scope": "Mail.Read User.Read",
                    }
                ]
            }
        },
    )
    assert result.status == FindingStatus.GAP


def test_ga_count_bounds_ok() -> None:
    assignments = [{"principalId": f"u{i}", "roleDefinitionId": GA} for i in range(3)]
    result = evaluate_ga_count_bounds(
        _check("id-ga-count-bounds"),
        {"role_assignments": assignments},
    )
    assert result.status == FindingStatus.OK


def test_ga_count_bounds_too_many_gap() -> None:
    assignments = [{"principalId": f"u{i}", "roleDefinitionId": GA} for i in range(12)]
    result = evaluate_ga_count_bounds(
        _check("id-ga-count-bounds"),
        {"role_assignments": assignments},
    )
    assert result.status == FindingStatus.GAP


def test_pim_no_permanent_gap() -> None:
    result = evaluate_pim_no_permanent_privileged(
        _check("id-pim-no-permanent-privileged"),
        {
            "role_assignments": [
                {"principalId": "u1", "roleDefinitionId": GA},
            ],
            "role_eligibilities": [],
        },
    )
    assert result.status == FindingStatus.GAP


def test_guest_directory_member_like_gap() -> None:
    result = evaluate_guest_directory_access_limited(
        _check("id-guest-directory-access-limited"),
        {"authorization_policy": {"guestUserRoleId": "a0b1b346-4d3e-4e8b-98f8-753987be4970"}},
    )
    assert result.status == FindingStatus.GAP


def test_password_never_expire_gap() -> None:
    result = evaluate_password_never_expire(
        _check("id-password-never-expire"),
        {
            "domains": [
                {
                    "id": "contoso.com",
                    "isVerified": True,
                    "passwordValidityPeriodInDays": 90,
                }
            ]
        },
    )
    assert result.status == FindingStatus.GAP


def test_password_never_expire_ok() -> None:
    result = evaluate_password_never_expire(
        _check("id-password-never-expire"),
        {
            "domains": [
                {
                    "id": "contoso.com",
                    "isVerified": True,
                    "passwordValidityPeriodInDays": 2147483647,
                }
            ]
        },
    )
    assert result.status == FindingStatus.OK
