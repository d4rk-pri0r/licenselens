"""Negative-case semantics tests for identity evaluators (maturity-1.0 task 4).

Locks the "OK is only OK when the protection is actually configured" contract:

- ``id-auth-authenticator-context``: GAP when Authenticator is not enabled.
- ``id-security-defaults``: OK only when defaults are ON or CA coverage is demonstrated.
- ``id-pim-unused``: 10 standing + 10 eligible must NOT be OK.
- ``id-access-reviews-unused``: presence-only reviews must NOT be OK.
- ``id-priv-dormant-accounts``: dormant/unverifiable service principals holding
  privileged roles must be flagged, never silently skipped.

Several of these are failing-first proofs: they fail against the pre-fix
evaluators and pass afterwards.
"""

from __future__ import annotations

from licenselens.collectors.privileged_roles import GLOBAL_ADMIN_TEMPLATE_ID
from licenselens.engine.evaluate import (
    evaluate_access_reviews_unused,
    evaluate_auth_authenticator_context,
    evaluate_dormant_privileged,
    evaluate_pim_unused,
    evaluate_security_defaults_on,
)
from licenselens.models import CheckDefinition, FindingStatus, Workload

_SECURITY_ADMIN_TEMPLATE_ID = "194ae4cb-b126-40b2-bd5b-6091b380977d"


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=Workload.IDENTITY)


def _auth_bundle(*configs: dict) -> dict:
    return {"auth_methods_bundle": {"configurations": list(configs)}}


# -- Authenticator context -----------------------------------------------------


def test_authenticator_disabled_is_not_ok():
    """Failing-first: disabled Authenticator must not report OK (was OK)."""
    result = evaluate_auth_authenticator_context(
        _check("id-auth-authenticator-context"),
        _auth_bundle({"id": "microsoftAuthenticator", "state": "disabled"}),
    )
    assert result.status == FindingStatus.GAP
    assert result.evidence["authenticator_state"] == "disabled"


def test_authenticator_missing_is_partial():
    result = evaluate_auth_authenticator_context(
        _check("id-auth-authenticator-context"),
        _auth_bundle({"id": "fido2", "state": "enabled"}),
    )
    assert result.status == FindingStatus.PARTIAL
    assert result.evidence["authenticator_present"] is False


def test_authenticator_enabled_with_context_is_ok():
    result = evaluate_auth_authenticator_context(
        _check("id-auth-authenticator-context"),
        _auth_bundle(
            {
                "id": "microsoftAuthenticator",
                "state": "enabled",
                "featureSettings": {
                    "displayAppInformationRequiredState": {"state": "enabled"},
                    "displayLocationInformationRequiredState": {"state": "enabled"},
                },
            }
        ),
    )
    assert result.status == FindingStatus.OK


def test_authenticator_enabled_number_matching_off_is_not_ok():
    """Failing-first: context alone is not OK when number matching is off."""
    result = evaluate_auth_authenticator_context(
        _check("id-auth-authenticator-context"),
        _auth_bundle(
            {
                "id": "microsoftAuthenticator",
                "state": "enabled",
                "featureSettings": {
                    "displayAppInformationRequiredState": {"state": "enabled"},
                    "displayLocationInformationRequiredState": {"state": "enabled"},
                    "numberMatchingRequiredState": {"state": "disabled"},
                },
            }
        ),
    )
    assert result.status != FindingStatus.OK


# -- Security defaults ---------------------------------------------------------


def test_security_defaults_off_without_ca_is_not_ok():
    """Failing-first: defaults OFF + zero CA policies must not report OK (was OK)."""
    result = evaluate_security_defaults_on(
        _check("id-security-defaults-on"),
        {"security_defaults_policy": {"id": "p", "isEnabled": False}, "ca_policies": []},
    )
    assert result.status == FindingStatus.GAP


def test_security_defaults_off_with_unknown_ca_is_partial():
    """Failing-first: defaults OFF with no CA evidence is PARTIAL, not OK."""
    result = evaluate_security_defaults_on(
        _check("id-security-defaults-on"),
        {"security_defaults_policy": {"id": "p", "isEnabled": False}},
    )
    assert result.status == FindingStatus.PARTIAL


def test_security_defaults_off_with_enabled_ca_is_ok():
    result = evaluate_security_defaults_on(
        _check("id-security-defaults-on"),
        {
            "security_defaults_policy": {"id": "p", "isEnabled": False},
            "ca_policies": [{"id": "ca-1", "state": "enabled"}],
        },
    )
    assert result.status == FindingStatus.OK


def test_security_defaults_off_with_only_report_only_ca_is_not_ok():
    """Failing-first: report-only CA does not demonstrate enforced coverage."""
    result = evaluate_security_defaults_on(
        _check("id-security-defaults-on"),
        {
            "security_defaults_policy": {"id": "p", "isEnabled": False},
            "ca_policies": [
                {"id": "ca-1", "state": "enabledForReportingButNotEnforced"},
                {"id": "ca-2", "state": "disabled"},
            ],
        },
    )
    assert result.status != FindingStatus.OK


def test_security_defaults_on_is_gap():
    result = evaluate_security_defaults_on(
        _check("id-security-defaults-on"),
        {"security_defaults_policy": {"id": "p", "isEnabled": True}, "ca_policies": []},
    )
    assert result.status == FindingStatus.GAP
    assert result.evidence["security_defaults_enabled"] is True


# -- PIM unused ----------------------------------------------------------------


def _assignment(pid: str, role: str = GLOBAL_ADMIN_TEMPLATE_ID) -> dict:
    return {"principalId": pid, "roleDefinitionId": role}


def test_pim_ten_standing_ten_eligible_is_not_ok():
    """Failing-first: many standing assignments are NOT masked by equal eligibilities."""
    result = evaluate_pim_unused(
        _check("id-pim-unused"),
        {
            "role_assignments": [
                _assignment(f"standing-{i}", _SECURITY_ADMIN_TEMPLATE_ID) for i in range(10)
            ],
            "role_eligibilities": [
                {"principalId": f"eligible-{i}", "roleDefinitionId": _SECURITY_ADMIN_TEMPLATE_ID}
                for i in range(10)
            ],
        },
    )
    assert result.status != FindingStatus.OK
    assert result.status in {FindingStatus.GAP, FindingStatus.PARTIAL}
    assert result.evidence["standing_non_break_glass_assignments"] == 10


def test_pim_break_glass_standing_with_coverage_is_ok():
    """Failing-first: standing assignments justified as break-glass + eligible coverage => OK."""
    result = evaluate_pim_unused(
        _check("id-pim-unused"),
        {
            "role_assignments": [
                _assignment("bg-1"),
                _assignment("bg-2"),
            ],
            "role_eligibilities": [
                {"principalId": "eligible-1", "roleDefinitionId": GLOBAL_ADMIN_TEMPLATE_ID},
            ],
            "break_glass_principal_ids": ["bg-1", "bg-2"],
        },
    )
    assert result.status == FindingStatus.OK


def test_pim_standing_roles_without_eligible_coverage_is_partial():
    """Break-glass standing roles must still have an eligible schedule for that role."""
    result = evaluate_pim_unused(
        _check("id-pim-unused"),
        {
            "role_assignments": [_assignment("bg-1")],
            "role_eligibilities": [
                {"principalId": "eligible-1", "roleDefinitionId": _SECURITY_ADMIN_TEMPLATE_ID},
            ],
            "break_glass_principal_ids": ["bg-1"],
        },
    )
    assert result.status == FindingStatus.PARTIAL


def test_pim_standing_without_eligibilities_is_gap():
    result = evaluate_pim_unused(
        _check("id-pim-unused"),
        {
            "role_assignments": [_assignment("standing-1")],
            "role_eligibilities": [],
        },
    )
    assert result.status == FindingStatus.GAP


# -- Access reviews ------------------------------------------------------------


def test_access_reviews_presence_only_is_not_ok():
    """Failing-first: definitions that don't provably cover privileged roles
    and recur must not report OK (was OK)."""
    result = evaluate_access_reviews_unused(
        _check("id-access-reviews-unused"),
        {
            "access_review_definitions": [
                {"id": "ar-1", "displayName": "Guest review"},
                {"id": "ar-2", "displayName": "Admin review"},
            ]
        },
    )
    assert result.status != FindingStatus.OK
    assert result.evidence["definition_count"] == 2


def test_access_reviews_privileged_and_recurring_is_ok():
    result = evaluate_access_reviews_unused(
        _check("id-access-reviews-unused"),
        {
            "access_review_definitions": [
                {
                    "id": "ar-priv",
                    "displayName": "Quarterly review of Global Administrators",
                    "scope": {
                        "principalScopes": [
                            {
                                "query": (
                                    "/roleManagement/directory/roleDefinitions/"
                                    + GLOBAL_ADMIN_TEMPLATE_ID
                                ),
                                "queryType": "MicrosoftGraph",
                            }
                        ],
                    },
                    "settings": {
                        "recurrence": {
                            "pattern": {"type": "absoluteMonthly"},
                            "range": {"type": "noEnd"},
                        },
                    },
                }
            ]
        },
    )
    assert result.status == FindingStatus.OK
    assert result.evidence["privileged_recurring_count"] == 1


def test_access_reviews_privileged_not_recurring_is_partial():
    """Failing-first: privileged-scope review without recurrence is PARTIAL."""
    result = evaluate_access_reviews_unused(
        _check("id-access-reviews-unused"),
        {
            "access_review_definitions": [
                {
                    "id": "ar-once",
                    "displayName": "Global Administrator access review",
                    "scope": {
                        "principalScopes": [
                            {
                                "query": "/roleManagement/directory/roleDefinitions/",
                                "queryType": "MicrosoftGraph",
                            }
                        ],
                    },
                }
            ]
        },
    )
    assert result.status == FindingStatus.PARTIAL


def test_access_reviews_recurring_but_not_privileged_is_partial():
    """Failing-first: a recurring guest review alone is not OK."""
    result = evaluate_access_reviews_unused(
        _check("id-access-reviews-unused"),
        {
            "access_review_definitions": [
                {
                    "id": "ar-guest",
                    "displayName": "Guest access review",
                    "scope": {
                        "principalScopes": [
                            {
                                "query": "/groups/11111111-1111-1111-1111-111111111111",
                                "queryType": "MicrosoftGraph",
                            }
                        ],
                    },
                    "settings": {
                        "recurrence": {
                            "pattern": {"type": "absoluteMonthly"},
                            "range": {"type": "noEnd"},
                        },
                    },
                }
            ]
        },
    )
    assert result.status == FindingStatus.PARTIAL


def test_access_reviews_none_is_gap():
    result = evaluate_access_reviews_unused(
        _check("id-access-reviews-unused"),
        {"access_review_definitions": []},
    )
    assert result.status == FindingStatus.GAP


# -- Dormant privileged / workload identities ----------------------------------


_SP_DIRECTORY = {
    "sp-dormant": {
        "id": "sp-dormant",
        "@odata.type": "#microsoft.graph.servicePrincipal",
        "accountEnabled": True,
        "appId": "00000000-0000-4000-8000-0000000000aa",
        "keyCredentials": [],
        "passwordCredentials": [],
    },
    "sp-cred": {
        "id": "sp-cred",
        "@odata.type": "#microsoft.graph.servicePrincipal",
        "accountEnabled": True,
        "appId": "00000000-0000-4000-8000-0000000000bb",
        "keyCredentials": [{"keyId": "00000000-0000-4000-8000-0000000000cc"}],
        "passwordCredentials": [{"displayName": "client-secret"}],
    },
    "sp-active": {
        "id": "sp-active",
        "@odata.type": "#microsoft.graph.servicePrincipal",
        "accountEnabled": True,
        "appId": "00000000-0000-4000-8000-0000000000dd",
        "keyCredentials": [{"keyId": "00000000-0000-4000-8000-0000000000ee"}],
        "passwordCredentials": [],
    },
    "sp-unknown": {
        "id": "sp-unknown",
        "@odata.type": "#microsoft.graph.servicePrincipal",
        "accountEnabled": True,
        "appId": "00000000-0000-4000-8000-0000000000ff",
    },
}


def test_dormant_service_principal_without_credentials_is_flagged():
    """Failing-first: an SP with a privileged role and no credentials must be flagged."""
    result = evaluate_dormant_privileged(
        _check("id-dormant-privileged"),
        {
            "role_assignments": [_assignment("sp-dormant")],
            "recent_signin_user_ids": set(),
            "principal_directory": {"sp-dormant": _SP_DIRECTORY["sp-dormant"]},
            "signin_lookback_days": 90,
            "signin_sample_truncated": False,
        },
    )
    assert result.status != FindingStatus.OK
    assert result.status in {FindingStatus.GAP, FindingStatus.PARTIAL}
    assert result.evidence["dormant_workload_identities"] >= 1


def test_dormant_service_principal_unverifiable_is_partial():
    """Failing-first: enabled SP with credentials but no usage signal => PARTIAL, never OK."""
    result = evaluate_dormant_privileged(
        _check("id-dormant-privileged"),
        {
            "role_assignments": [_assignment("sp-cred")],
            "recent_signin_user_ids": set(),
            "principal_directory": {"sp-cred": _SP_DIRECTORY["sp-cred"]},
            "signin_lookback_days": 90,
            "signin_sample_truncated": False,
        },
    )
    assert result.status == FindingStatus.PARTIAL
    assert result.evidence["unverifiable_workload_identities"] >= 1
    assert "workload" in result.summary.lower()


def test_dormant_service_principal_unknown_credentials_is_partial():
    """Failing-first: SP with no credential fields at all must not silently pass."""
    result = evaluate_dormant_privileged(
        _check("id-dormant-privileged"),
        {
            "role_assignments": [_assignment("sp-unknown")],
            "recent_signin_user_ids": set(),
            "principal_directory": {"sp-unknown": _SP_DIRECTORY["sp-unknown"]},
            "signin_lookback_days": 90,
            "signin_sample_truncated": False,
        },
    )
    assert result.status == FindingStatus.PARTIAL
    assert result.evidence["unverifiable_workload_identities"] >= 1


def test_dormant_active_service_principal_is_ok():
    result = evaluate_dormant_privileged(
        _check("id-dormant-privileged"),
        {
            "role_assignments": [_assignment("sp-active")],
            "recent_signin_user_ids": {"sp-active"},
            "principal_directory": {"sp-active": _SP_DIRECTORY["sp-active"]},
            "signin_lookback_days": 90,
            "signin_sample_truncated": False,
        },
    )
    assert result.status == FindingStatus.OK
    assert result.evidence["dormant_workload_identities"] == 0
    assert result.evidence["unverifiable_workload_identities"] == 0


def test_dormant_disabled_service_principal_is_not_dormant():
    result = evaluate_dormant_privileged(
        _check("id-dormant-privileged"),
        {
            "role_assignments": [_assignment("sp-disabled")],
            "recent_signin_user_ids": set(),
            "principal_directory": {
                "sp-disabled": {
                    "id": "sp-disabled",
                    "@odata.type": "#microsoft.graph.servicePrincipal",
                    "accountEnabled": False,
                    "appId": "00000000-0000-4000-8000-0000000000ab",
                    "keyCredentials": [],
                    "passwordCredentials": [],
                }
            },
            "signin_lookback_days": 90,
            "signin_sample_truncated": False,
        },
    )
    assert result.status == FindingStatus.OK
    assert result.evidence["dormant_workload_identities"] == 0
    assert result.evidence["disabled_or_unresolved"] >= 1
