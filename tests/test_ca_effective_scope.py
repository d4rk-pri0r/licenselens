"""WS1-A: Conditional Access effective-scope semantics (PolicyScope + ladder).

Graph property shape from the conditionalAccessConditionSet family:
https://learn.microsoft.com/graph/api/resources/conditionalaccessconditionset
plus conditionalAccessApplications (includeApplications ``All``/``None``/ids,
includeUserActions), conditionalAccessLocations (excludeLocations
``AllTrusted`` or namedLocation ids), conditionalAccessPlatforms
(includePlatforms/excludePlatforms, value ``all``), and conditionalAccessDevices
(deviceFilter.rule).
"""

from __future__ import annotations

from typing import Any

import pytest

from licenselens.collectors.conditional_access import (
    DEMO_CA_POLICIES,
    LEGACY_CLIENT_APP_TYPES,
    SCOPE_GAP_TOKENS,
    policy_scope,
    scope_for_block,
)
from licenselens.engine.evaluate import (
    evaluate_ca_legacy_auth_block,
    evaluate_ca_mfa_all_users,
    evaluate_ca_mfa_registration_managed,
    evaluate_ca_phishing_resistant_all,
    evaluate_ca_phishing_resistant_privileged,
    evaluate_ca_priv_gaps,
)
from licenselens.engine.loader import load_checks
from licenselens.engine.runner import _evaluate_check
from licenselens.evaluators.identity_ca_lib import purpose_scope
from licenselens.models import CheckDefinition, FindingStatus, Workload

GA_ROLE = "62e90394-69f5-4237-9190-012177145e10"


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=Workload.IDENTITY)


def _conditions(**overrides: Any) -> dict:
    base: dict = {
        "users": {"includeUsers": ["All"]},
        "applications": {"includeApplications": ["All"]},
        "clientAppTypes": ["all"],
    }
    return {**base, **overrides}


def _policy(conditions: dict) -> dict:
    return {
        "id": "policy-1",
        "displayName": "policy",
        "state": "enabled",
        "conditions": conditions,
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    }


# ---------------------------------------------------------------------------
# Scope model: users / applications / userActions
# ---------------------------------------------------------------------------


def test_scope_all_users_all_apps_is_universal() -> None:
    scope = policy_scope(_policy(_conditions()))
    assert scope.all_users is True
    assert scope.all_cloud_apps is True
    assert scope.gaps == ()
    assert scope.is_universal is True


def test_scope_single_app_not_universal() -> None:
    scope = policy_scope(_policy(_conditions(applications={"includeApplications": ["app-1"]})))
    assert scope.all_cloud_apps is False
    assert scope.gaps == ("not_all_cloud_apps",)
    assert scope.is_universal is False


def test_scope_include_none_not_universal() -> None:
    # "None" is the Graph sentinel that excludes every cloud app.
    scope = policy_scope(_policy(_conditions(applications={"includeApplications": ["None"]})))
    assert scope.all_cloud_apps is False
    assert scope.user_actions_only is False
    assert scope.gaps == ("not_all_cloud_apps",)


def test_scope_absent_applications_block_not_universal() -> None:
    scope = policy_scope(_policy({"users": {"includeUsers": ["All"]}, "clientAppTypes": ["all"]}))
    assert scope.all_cloud_apps is False
    assert scope.gaps == ("not_all_cloud_apps",)


def test_scope_user_actions_only_single_token() -> None:
    scope = policy_scope(
        _policy(_conditions(applications={"includeUserActions": ["urn:user:registersecurityinfo"]}))
    )
    assert scope.user_actions_only is True
    # One token for one cause: not_all_cloud_apps is NOT co-emitted.
    assert scope.gaps == ("user_actions_only",)


def test_scope_excluded_apps_informational_not_gap() -> None:
    scope = policy_scope(
        _policy(
            _conditions(
                applications={
                    "includeApplications": ["All"],
                    "excludeApplications": ["app-9", "app-2"],
                }
            )
        )
    )
    assert scope.excluded_apps == ("app-2", "app-9")
    assert scope.gaps == ()
    assert scope.is_universal is True


# ---------------------------------------------------------------------------
# Scope model: risk conditions
# ---------------------------------------------------------------------------


def test_scope_sign_in_risk_is_conditioned() -> None:
    scope = policy_scope(_policy(_conditions(signInRiskLevels=["medium", "high"])))
    assert scope.risk_conditioned is True
    assert scope.gaps == ("risk_conditioned",)


def test_scope_user_risk_is_conditioned() -> None:
    scope = policy_scope(_policy(_conditions(userRiskLevels=["high"])))
    assert scope.risk_conditioned is True
    assert scope.gaps == ("risk_conditioned",)


def test_scope_sp_risk_is_conditioned() -> None:
    scope = policy_scope(_policy(_conditions(servicePrincipalRiskLevels=["low"])))
    assert scope.risk_conditioned is True
    assert scope.gaps == ("risk_conditioned",)


# ---------------------------------------------------------------------------
# Scope model: clientAppTypes / platforms
# ---------------------------------------------------------------------------


def test_scope_browser_only_is_client_subset() -> None:
    scope = policy_scope(_policy(_conditions(clientAppTypes=["browser"])))
    assert scope.all_client_apps is False
    assert scope.gaps == ("client_app_subset",)


def test_scope_android_only_is_platform_subset() -> None:
    scope = policy_scope(_policy(_conditions(platforms={"includePlatforms": ["android"]})))
    assert scope.all_platforms is False
    assert scope.gaps == ("platform_subset",)


def test_scope_exclude_platform_is_subset() -> None:
    scope = policy_scope(
        _policy(_conditions(platforms={"includePlatforms": [], "excludePlatforms": ["windows"]}))
    )
    assert scope.all_platforms is False
    assert scope.gaps == ("platform_subset",)


def test_scope_platforms_all_is_universal() -> None:
    scope = policy_scope(
        _policy(_conditions(platforms={"includePlatforms": ["all"], "excludePlatforms": []}))
    )
    assert scope.all_platforms is True
    assert scope.gaps == ()


# ---------------------------------------------------------------------------
# Scope model: locations / devices / token vocabulary
# ---------------------------------------------------------------------------


def test_scope_all_trusted_exclusion_is_trusted_bypass() -> None:
    scope = policy_scope(_policy(_conditions(locations={"excludeLocations": ["AllTrusted"]})))
    assert scope.location_bypass == ("AllTrusted",)
    assert scope.gaps == ("trusted_location_bypass",)


def test_scope_named_location_exclusion_is_named_bypass() -> None:
    scope = policy_scope(_policy(_conditions(locations={"excludeLocations": ["loc-1"]})))
    assert scope.location_bypass == ("loc-1",)
    assert scope.gaps == ("named_location_bypass",)


def test_scope_both_bypass_tokens() -> None:
    scope = policy_scope(
        _policy(_conditions(locations={"excludeLocations": ["loc-2", "AllTrusted"]}))
    )
    assert scope.location_bypass == ("AllTrusted", "loc-2")
    assert scope.gaps == ("trusted_location_bypass", "named_location_bypass")


def test_scope_device_filter_flagged() -> None:
    scope = policy_scope(
        _policy(_conditions(devices={"deviceFilter": {"rule": "device.trustType -eq 'AzureAD'"}}))
    )
    assert scope.device_filter is True
    assert scope.gaps == ("device_filter",)


def test_scope_device_filter_empty_rule_not_flagged() -> None:
    scope = policy_scope(_policy(_conditions(devices={"deviceFilter": {"rule": ""}})))
    assert scope.device_filter is False
    assert scope.gaps == ()


def test_gaps_are_ordered_and_closed_vocabulary() -> None:
    everything = _policy(
        {
            "users": {"includeUsers": ["user-1"]},
            "applications": {
                "includeApplications": ["app-1"],
                "excludeApplications": ["app-2"],
            },
            "clientAppTypes": ["browser"],
            "signInRiskLevels": ["high"],
            "platforms": {"includePlatforms": ["android"], "excludePlatforms": []},
            "locations": {"excludeLocations": ["AllTrusted", "loc-1"]},
            "devices": {"deviceFilter": {"rule": "device.isCompliant -eq true"}},
        }
    )
    scope = policy_scope(everything)
    expected = tuple(t for t in SCOPE_GAP_TOKENS if t != "user_actions_only")
    assert scope.gaps == expected
    assert set(scope.gaps) <= set(SCOPE_GAP_TOKENS)
    assert scope.is_universal is False
    # excluded_apps stays informational even here.
    assert scope.excluded_apps == ("app-2",)

    actions_only = _policy(
        _conditions(applications={"includeUserActions": ["urn:user:registersecurityinfo"]})
    )
    assert policy_scope(actions_only).gaps == ("user_actions_only",)


# ---------------------------------------------------------------------------
# Block-purpose scope: allowed client subset is not a gap
# ---------------------------------------------------------------------------


def test_block_scope_legacy_subset_not_gap() -> None:
    policy = _policy(_conditions(clientAppTypes=["exchangeActiveSync", "other"]))
    policy["grantControls"] = {"operator": "OR", "builtInControls": ["block"]}
    scope = scope_for_block(policy, allowed_client_subset=LEGACY_CLIENT_APP_TYPES)
    assert scope.all_client_apps is True
    assert scope.is_universal is True


def test_block_scope_single_app_is_gap() -> None:
    policy = _policy(
        _conditions(
            applications={"includeApplications": ["app-1"]},
            clientAppTypes=["exchangeActiveSync", "other"],
        )
    )
    scope = scope_for_block(policy, allowed_client_subset=LEGACY_CLIENT_APP_TYPES)
    assert scope.gaps == ("not_all_cloud_apps",)


def test_block_scope_android_only_is_gap() -> None:
    policy = _policy(
        _conditions(
            clientAppTypes=["exchangeActiveSync", "other"],
            platforms={"includePlatforms": ["android"]},
        )
    )
    scope = scope_for_block(policy, allowed_client_subset=LEGACY_CLIENT_APP_TYPES)
    assert scope.gaps == ("platform_subset",)


def test_block_scope_empty_subset_flags_browser_only() -> None:
    policy = _policy(_conditions(clientAppTypes=["browser"]))
    scope = scope_for_block(policy, allowed_client_subset=frozenset())
    assert scope.all_client_apps is False
    assert scope.gaps == ("client_app_subset",)


# ---------------------------------------------------------------------------
# Coverage ladder (through the real evaluators)
# ---------------------------------------------------------------------------


def _mfa_policy(conditions: dict, *, name: str = "Matrix MFA") -> dict:
    return {
        "id": "matrix-mfa",
        "displayName": name,
        "state": "enabled",
        "conditions": conditions,
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    }


_UNIVERSAL = {
    "users": {"includeUsers": ["All"]},
    "applications": {"includeApplications": ["All"]},
    "clientAppTypes": ["all"],
}


def _single_app_conditions() -> dict:
    return _conditions(applications={"includeApplications": ["app-1"]})


@pytest.mark.parametrize(
    ("conditions", "expected", "expected_gaps"),
    [
        pytest.param(
            _conditions(signInRiskLevels=["medium"]),
            FindingStatus.PARTIAL,
            ["risk_conditioned"],
            id="risk-only",
        ),
        pytest.param(
            _single_app_conditions(),
            FindingStatus.PARTIAL,
            ["not_all_cloud_apps"],
            id="single-app",
        ),
        pytest.param(
            _conditions(locations={"excludeLocations": ["AllTrusted"]}),
            FindingStatus.PARTIAL,
            ["trusted_location_bypass"],
            id="all-trusted",
        ),
        pytest.param(
            _conditions(clientAppTypes=["browser"]),
            FindingStatus.PARTIAL,
            ["client_app_subset"],
            id="browser-only",
        ),
        pytest.param(
            _conditions(platforms={"includePlatforms": ["android"]}),
            FindingStatus.PARTIAL,
            ["platform_subset"],
            id="android-only",
        ),
        pytest.param(
            _conditions(applications={"includeApplications": None}),
            FindingStatus.PARTIAL,
            ["not_all_cloud_apps"],
            id="include-applications-none",
        ),
        pytest.param(
            _conditions(applications={"includeUserActions": ["urn:user:registersecurityinfo"]}),
            FindingStatus.PARTIAL,
            ["user_actions_only"],
            id="user-actions-only",
        ),
        pytest.param(
            _conditions(),
            FindingStatus.OK,
            None,
            id="clean-universal",
        ),
        pytest.param(
            _conditions(users={"includeUsers": ["All"], "excludeGroups": ["group-x"]}),
            FindingStatus.PARTIAL,
            None,
            id="universal-unjustified-exclude-groups",
        ),
    ],
)
def test_mfa_all_users_matrix(
    conditions: dict, expected: FindingStatus, expected_gaps: list[str] | None
) -> None:
    result = evaluate_ca_mfa_all_users(
        _check("id-ca-mfa-all-users"),
        {"ca_policies": [_mfa_policy(conditions)], "break_glass_principal_ids": []},
    )
    assert result.status is expected
    if expected_gaps is not None:
        assert result.evidence["scope_gaps_best"] == expected_gaps
    if "excludeGroups" in conditions["users"]:
        assert "break-glass" in result.summary
        assert result.evidence["unjustified_exclusion_issues"]


def test_scoped_partial_lists_best_policy_first() -> None:
    narrow = _mfa_policy(_single_app_conditions(), name="Zulu narrow")
    broad = _mfa_policy(
        _conditions(
            applications={"includeApplications": ["app-1"]},
            clientAppTypes=["browser"],
            platforms={"includePlatforms": ["android"]},
            signInRiskLevels=["low"],
        ),
        name="Alpha broad",
    )
    result = evaluate_ca_mfa_all_users(
        _check("id-ca-mfa-all-users"),
        {"ca_policies": [broad, narrow], "break_glass_principal_ids": []},
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.evidence["scope_gaps_best"] == ["not_all_cloud_apps"]
    # Fewest gaps wins even though Alpha < Zulu alphabetically.
    assert result.evidence["scoped_policies"][0] == {
        "policy": "Zulu narrow",
        "gaps": ["not_all_cloud_apps"],
    }
    assert result.evidence["scoped_policies"][1]["policy"] == "Alpha broad"
    assert len(result.evidence["scoped_policies"]) == 2


def test_scoped_partial_adds_joint_coverage_limitation() -> None:
    result = evaluate_ca_mfa_all_users(
        _check("id-ca-mfa-all-users"),
        {"ca_policies": [_mfa_policy(_single_app_conditions())], "break_glass_principal_ids": []},
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.summary == (
        "MFA for all users: enforced policy exists but is scoped (not_all_cloud_apps)."
    )
    assert (
        "Joint coverage across several narrower Conditional Access policies is not "
        "computed; each scoped policy is listed so a reviewer can judge the union."
    ) in result.limitations


def test_evidence_keys_always_present() -> None:
    universal = _mfa_policy(_conditions())
    scoped = _mfa_policy(_single_app_conditions())
    for policies in ([universal], [scoped], []):
        result = evaluate_ca_mfa_all_users(
            _check("id-ca-mfa-all-users"),
            {"ca_policies": policies, "break_glass_principal_ids": []},
        )
        for key in ("universal_policies", "scoped_policies", "scope_gaps_best"):
            assert key in result.evidence
    gap = evaluate_ca_mfa_all_users(
        _check("id-ca-mfa-all-users"), {"ca_policies": [], "break_glass_principal_ids": []}
    )
    assert gap.evidence["universal_policies"] == []
    assert gap.evidence["scoped_policies"] == []
    assert gap.evidence["scope_gaps_best"] == []


def test_universal_plus_scoped_is_ok_when_universal_clean() -> None:
    universal = _mfa_policy(_conditions(), name="Universal MFA")
    scoped = _mfa_policy(_single_app_conditions(), name="Scoped MFA")
    result = evaluate_ca_mfa_all_users(
        _check("id-ca-mfa-all-users"),
        {"ca_policies": [scoped, universal], "break_glass_principal_ids": []},
    )
    assert result.status is FindingStatus.OK
    assert result.evidence["universal_policies"] == ["Universal MFA"]
    assert result.evidence["scoped_policies"][0]["policy"] == "Scoped MFA"
    # Backward compatibility: enforced_policies still lists ALL enforced.
    assert set(result.evidence["enforced_policies"]) == {"Universal MFA", "Scoped MFA"}


# ---------------------------------------------------------------------------
# Role-targeted policies: role targeting is the purpose, not a gap
# ---------------------------------------------------------------------------


def test_purpose_scope_clears_only_named_dimensions() -> None:
    policy = _policy(
        {
            "users": {"includeUsers": [], "includeRoles": [GA_ROLE]},
            "applications": {"includeApplications": ["app-1"]},
        }
    )
    scope = purpose_scope(all_users=True)(policy)
    assert scope.gaps == ("not_all_cloud_apps",)


def test_role_targeted_policy_scoped_only_by_non_user_dimensions() -> None:
    def _pr_policy(include_applications: list[str]) -> dict:
        return {
            "id": "pr-admins",
            "displayName": "PR MFA admins",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": [], "includeRoles": [GA_ROLE]},
                "applications": {"includeApplications": include_applications},
            },
            "grantControls": {
                "authenticationStrength": {
                    "id": "00000000-0000-0000-0000-000000000003",
                    "displayName": "Phishing-resistant MFA",
                }
            },
        }

    ok = evaluate_ca_phishing_resistant_privileged(
        _check("id-ca-phishing-resistant-privileged"),
        {"ca_policies": [_pr_policy(["All"])]},
    )
    assert ok.status is FindingStatus.OK
    assert ok.evidence["universal_policies"] == ["PR MFA admins"]
    assert ok.evidence["scope_gaps_best"] == []

    partial = evaluate_ca_phishing_resistant_privileged(
        _check("id-ca-phishing-resistant-privileged"),
        {"ca_policies": [_pr_policy(["app-1"])]},
    )
    assert partial.status is FindingStatus.PARTIAL
    assert partial.evidence["scope_gaps_best"] == ["not_all_cloud_apps"]


# ---------------------------------------------------------------------------
# Legacy-auth block matrix (client subset is the policy's purpose)
# ---------------------------------------------------------------------------


def _block_policy(conditions: dict) -> dict:
    return {
        "id": "matrix-block",
        "displayName": "Matrix block",
        "state": "enabled",
        "conditions": conditions,
        "grantControls": {"operator": "OR", "builtInControls": ["block"]},
    }


@pytest.mark.parametrize(
    ("conditions", "expected", "expected_gaps"),
    [
        pytest.param(
            _conditions(clientAppTypes=["browser"]),
            FindingStatus.GAP,
            None,
            id="browser-only",
        ),
        pytest.param(
            _conditions(
                applications={"includeApplications": ["app-1"]},
                clientAppTypes=["exchangeActiveSync"],
            ),
            FindingStatus.PARTIAL,
            ["not_all_cloud_apps"],
            id="single-app",
        ),
        pytest.param(
            _conditions(
                clientAppTypes=["exchangeActiveSync", "other"],
                platforms={"includePlatforms": ["android"]},
            ),
            FindingStatus.PARTIAL,
            ["platform_subset"],
            id="android-only",
        ),
        pytest.param(
            _conditions(clientAppTypes=["exchangeActiveSync", "other"]),
            FindingStatus.OK,
            None,
            id="exact-legacy-subset",
        ),
    ],
)
def test_legacy_block_matrix(
    conditions: dict, expected: FindingStatus, expected_gaps: list[str] | None
) -> None:
    result = evaluate_ca_legacy_auth_block(
        _check("id-ca-legacy-auth-block"),
        {"ca_policies": [_block_policy(conditions)], "break_glass_principal_ids": []},
    )
    assert result.status is expected
    if expected_gaps is not None:
        assert result.evidence["scope_gaps_best"] == expected_gaps


# ---------------------------------------------------------------------------
# MFA registration (user actions are the policy's purpose)
# ---------------------------------------------------------------------------


def _registration_policy(conditions: dict) -> dict:
    return {
        "id": "matrix-registration",
        "displayName": "Matrix registration",
        "state": "enabled",
        "conditions": conditions,
        "grantControls": {"operator": "OR", "builtInControls": ["compliantDevice"]},
    }


_REGISTRATION_UNIVERSAL = {
    "users": {"includeUsers": ["All"]},
    "applications": {
        "includeApplications": [],
        "includeUserActions": ["urn:user:registersecurityinfo"],
    },
    "clientAppTypes": ["all"],
}


def test_mfa_registration_managed_user_action_policy_is_ok() -> None:
    result = evaluate_ca_mfa_registration_managed(
        _check("id-ca-mfa-registration-managed"),
        {
            "ca_policies": [_registration_policy(_REGISTRATION_UNIVERSAL)],
            "break_glass_principal_ids": [],
        },
    )
    assert result.status is FindingStatus.OK


def test_mfa_registration_managed_android_only_is_partial() -> None:
    conditions = {
        **_REGISTRATION_UNIVERSAL,
        "platforms": {"includePlatforms": ["android"], "excludePlatforms": []},
    }
    result = evaluate_ca_mfa_registration_managed(
        _check("id-ca-mfa-registration-managed"),
        {"ca_policies": [_registration_policy(conditions)], "break_glass_principal_ids": []},
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.evidence["scope_gaps_best"] == ["platform_subset"]


# ---------------------------------------------------------------------------
# Demo fixtures
# ---------------------------------------------------------------------------


def test_demo_mfa_all_is_universal() -> None:
    assert policy_scope(DEMO_CA_POLICIES[0]).is_universal is True


def test_demo_risk_policies_are_risk_conditioned() -> None:
    assert policy_scope(DEMO_CA_POLICIES[1]).gaps == ("risk_conditioned",)
    assert policy_scope(DEMO_CA_POLICIES[2]).gaps == ("risk_conditioned",)


# ---------------------------------------------------------------------------
# Security Defaults ladder (WS1-B): baseline visibility, never a false OK
# ---------------------------------------------------------------------------


def test_security_defaults_on_mfa_all_is_partial_paid_ca_unused() -> None:
    result = evaluate_ca_mfa_all_users(
        _check("id-ca-mfa-all-users"),
        {
            "ca_policies": [],
            "break_glass_principal_ids": [],
            "security_defaults_policy": {"id": "sd", "isEnabled": True},
        },
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.summary == (
        "Baseline protection is provided by Security Defaults; the "
        "Conditional Access capability you license is not in use."
    )
    assert result.evidence["security_defaults_enabled"] is True


def test_security_defaults_on_legacy_is_partial_paid_ca_unused() -> None:
    result = evaluate_ca_legacy_auth_block(
        _check("id-ca-legacy-auth-block"),
        {
            "ca_policies": [],
            "break_glass_principal_ids": [],
            "security_defaults_policy": {"isEnabled": True},
        },
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.evidence["security_defaults_enabled"] is True


def test_security_defaults_on_phishing_resistant_stays_gap_with_note() -> None:
    result = evaluate_ca_phishing_resistant_all(
        _check("id-ca-phishing-resistant-all"),
        {
            "ca_policies": [],
            "break_glass_principal_ids": [],
            "security_defaults_policy": {"isEnabled": True},
        },
    )
    assert result.status is FindingStatus.GAP
    assert (
        "Security Defaults is on; Conditional Access policies cannot be created "
        "until it is disabled."
    ) in result.limitations


def test_security_defaults_on_does_not_promote_scoped_mfa_to_ok() -> None:
    # Guard: the scoped branch outranks the Security Defaults step, both ways.
    scoped = _mfa_policy(_conditions(signInRiskLevels=["high"]), name="Risk MFA")
    result = evaluate_ca_mfa_all_users(
        _check("id-ca-mfa-all-users"),
        {
            "ca_policies": [scoped],
            "break_glass_principal_ids": [],
            "security_defaults_policy": {"isEnabled": True},
        },
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.summary == (
        "MFA for all users: enforced policy exists but is scoped (risk_conditioned)."
    )
    assert result.evidence["security_defaults_enabled"] is True


def test_security_defaults_off_absent_is_gap() -> None:
    for sd in ({}, {"isEnabled": False}):
        result = evaluate_ca_mfa_all_users(
            _check("id-ca-mfa-all-users"),
            {
                "ca_policies": [],
                "break_glass_principal_ids": [],
                "security_defaults_policy": sd,
            },
        )
        assert result.status is FindingStatus.GAP
        assert result.evidence["security_defaults_enabled"] is False


def test_evidence_always_has_security_defaults_enabled() -> None:
    cases = [
        ([_mfa_policy(_conditions())], None, FindingStatus.OK, False),
        ([_mfa_policy(_single_app_conditions())], None, FindingStatus.PARTIAL, False),
        ([], {"isEnabled": True}, FindingStatus.PARTIAL, True),
        ([], {"isEnabled": False}, FindingStatus.GAP, False),
    ]
    for policies, sd, expected_status, expected_flag in cases:
        evidence: dict[str, Any] = {
            "ca_policies": policies,
            "break_glass_principal_ids": [],
        }
        if sd is not None:
            evidence["security_defaults_policy"] = sd
        result = evaluate_ca_mfa_all_users(_check("id-ca-mfa-all-users"), evidence)
        assert result.status is expected_status
        assert result.evidence["security_defaults_enabled"] is expected_flag


# ---------------------------------------------------------------------------
# Runner boundary: a failed Security Defaults read must not ERROR a CA check
# ---------------------------------------------------------------------------


def test_ca_checks_do_not_error_when_security_defaults_read_fails() -> None:
    check = next(c for c in load_checks() if c.id == "id-ca-mfa-all-users")
    finding = _evaluate_check(
        check,
        set(check.required_capabilities),
        {
            "ca_policies": [],
            "break_glass_principal_ids": [],
            "security_defaults_policy_error": "403 Forbidden",
        },
    )
    assert finding.status in (FindingStatus.GAP, FindingStatus.PARTIAL)


# ---------------------------------------------------------------------------
# Privileged-gap filters (WS1-B): scope-aware coverage, not predicate-only
# ---------------------------------------------------------------------------


def test_priv_gaps_risk_only_mfa_does_not_clear() -> None:
    risk_mfa = _mfa_policy(_conditions(signInRiskLevels=["high"]), name="Risk MFA")
    legacy = _block_policy(_conditions(clientAppTypes=["exchangeActiveSync", "other"]))
    result = evaluate_ca_priv_gaps(
        _check("id-ca-priv-gaps"),
        {"ca_policies": [risk_mfa, legacy], "role_assignments": []},
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.evidence["mfa_covers_privileged"] is False


def test_priv_gaps_single_app_mfa_does_not_clear() -> None:
    single_app = _mfa_policy(_single_app_conditions(), name="Single-app MFA")
    legacy = _block_policy(_conditions(clientAppTypes=["exchangeActiveSync", "other"]))
    result = evaluate_ca_priv_gaps(
        _check("id-ca-priv-gaps"),
        {"ca_policies": [single_app, legacy], "role_assignments": []},
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.evidence["mfa_covers_privileged"] is False


def test_priv_gaps_single_app_legacy_block_does_not_clear() -> None:
    mfa = _mfa_policy(_conditions())
    legacy = _block_policy(
        _conditions(
            applications={"includeApplications": ["app-1"]},
            clientAppTypes=["exchangeActiveSync", "other"],
        )
    )
    result = evaluate_ca_priv_gaps(
        _check("id-ca-priv-gaps"),
        {"ca_policies": [mfa, legacy], "role_assignments": []},
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.evidence["legacy_block_enforced"] == []


def test_priv_gaps_role_targeted_mfa_all_apps_clears_mfa_leg() -> None:
    # Guard: existing behaviour preserved (brief D4 last paragraph).
    role_mfa = {
        "id": "role-mfa",
        "displayName": "MFA privileged",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": [], "includeRoles": [GA_ROLE]},
            "applications": {"includeApplications": ["All"]},
            "clientAppTypes": ["all"],
        },
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    }
    legacy = _block_policy(_conditions(clientAppTypes=["exchangeActiveSync", "other"]))
    result = evaluate_ca_priv_gaps(
        _check("id-ca-priv-gaps"),
        {
            "ca_policies": [role_mfa, legacy],
            "role_assignments": [
                {"principalId": "admin-1", "roleDefinitionId": GA_ROLE},
            ],
        },
    )
    assert result.status is FindingStatus.OK
    assert "mfa_missing_for_privileged" not in result.evidence["exposure_flags"]
