"""Conditional Access predicate semantics — maturity-1.0 task 3 regressions.

These lock three false-confidence fixes:

1. An OR-operator grant (e.g. "MFA OR password change") is NOT MFA-enforcing.
2. An empty/absent ``clientAppTypes`` block policy applies to ALL client
   types (Graph semantics), so it DOES block legacy authentication.
3. ``id-ca-priv-gaps`` applies the shared unjustified-exclusion analysis:
   a policy that excludes principals without a break-glass rationale does
   not clear the gap.
"""

from __future__ import annotations

from licenselens.collectors import conditional_access as ca
from licenselens.engine.evaluate import evaluate_ca_priv_gaps
from licenselens.models import CheckDefinition, ExposureClass, FindingStatus, Workload

GA_ROLE = "62e90394-69f5-4237-9190-012177145e10"


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=Workload.IDENTITY)


def _policy(**overrides: object) -> dict:
    policy: dict = {
        "displayName": "policy",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "clientAppTypes": ["all"],
        },
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    }
    for key, value in overrides.items():
        if value is None:
            policy.pop(key, None)
        else:
            policy[key] = value
    return policy


# ---------------------------------------------------------------------------
# 1. OR-operator grants are not MFA-enforcing
# ---------------------------------------------------------------------------


def test_requires_mfa_or_grant_among_multiple_controls_is_not_enforced() -> None:
    """Failing-first proof: 'MFA OR passwordChange' must not count as MFA."""
    policy = _policy(
        grantControls={"operator": "OR", "builtInControls": ["mfa", "passwordChange"]},
    )
    assert ca.requires_mfa(policy) is False


def test_requires_mfa_and_grant_with_mfa_is_enforced() -> None:
    policy = _policy(
        grantControls={"operator": "AND", "builtInControls": ["mfa", "compliantDevice"]},
    )
    assert ca.requires_mfa(policy) is True


def test_requires_mfa_single_control_or_is_enforced() -> None:
    # A grant that IS MFA alone enforces MFA regardless of operator.
    policy = _policy(grantControls={"operator": "OR", "builtInControls": ["mfa"]})
    assert ca.requires_mfa(policy) is True


def test_requires_mfa_phantom_strengthauthentication_ignored() -> None:
    # "strengthauthentication" is not a valid builtInControls value; auth
    # strength is the separate authenticationStrength object.
    policy = _policy(grantControls={"builtInControls": ["strengthauthentication"]})
    assert ca.requires_mfa(policy) is False


def test_requires_mfa_authentication_strength_still_counts() -> None:
    policy = _policy(
        grantControls={
            "authenticationStrength": {
                "id": "00000000-0000-0000-0000-000000000004",
                "displayName": "Passwordless MFA",
            }
        },
    )
    assert ca.requires_mfa(policy) is True


def test_requires_managed_device_or_grant_is_not_enforced() -> None:
    policy = _policy(
        grantControls={"operator": "OR", "builtInControls": ["compliantDevice", "mfa"]},
    )
    assert ca.requires_managed_device(policy) is False


def test_requires_managed_device_and_grant_is_enforced() -> None:
    policy = _policy(
        grantControls={"operator": "AND", "builtInControls": ["compliantDevice", "mfa"]},
    )
    assert ca.requires_managed_device(policy) is True


# ---------------------------------------------------------------------------
# 2. Empty clientAppTypes means "all clients" (Graph semantics)
# ---------------------------------------------------------------------------


def test_is_legacy_auth_block_empty_client_app_types_blocks_legacy() -> None:
    policy = _policy(
        conditions={
            "users": {"includeUsers": ["All"]},
            "clientAppTypes": [],
        },
        grantControls={"builtInControls": ["block"]},
    )
    assert ca.is_legacy_auth_block(policy) is True


def test_is_legacy_auth_block_absent_client_app_types_blocks_legacy() -> None:
    policy = _policy(
        conditions={"users": {"includeUsers": ["All"]}},
        grantControls={"builtInControls": ["block"]},
    )
    assert ca.is_legacy_auth_block(policy) is True


def test_is_legacy_auth_block_all_client_app_types_blocks_legacy() -> None:
    policy = _policy(
        conditions={
            "users": {"includeUsers": ["All"]},
            "clientAppTypes": ["all"],
        },
        grantControls={"builtInControls": ["block"]},
    )
    assert ca.is_legacy_auth_block(policy) is True


def test_is_legacy_auth_block_modern_only_does_not_count() -> None:
    policy = _policy(
        conditions={
            "users": {"includeUsers": ["All"]},
            "clientAppTypes": ["browser"],
        },
        grantControls={"builtInControls": ["block"]},
    )
    assert ca.is_legacy_auth_block(policy) is False


def test_is_legacy_auth_block_mixed_legacy_modern_does_not_count() -> None:
    policy = _policy(
        conditions={
            "users": {"includeUsers": ["All"]},
            "clientAppTypes": ["exchangeActiveSync", "browser"],
        },
        grantControls={"builtInControls": ["block"]},
    )
    assert ca.is_legacy_auth_block(policy) is False


# ---------------------------------------------------------------------------
# 3. id-ca-priv-gaps applies the unjustified-exclusion analysis
# ---------------------------------------------------------------------------

_MFA_ALL = {
    "displayName": "MFA all",
    "state": "enabled",
    "conditions": {
        "users": {"includeUsers": ["All"], "excludeUsers": ["mystery-admin"]},
        "clientAppTypes": ["all"],
    },
    "grantControls": {"builtInControls": ["mfa"]},
}
_LEGACY_BLOCK = {
    "displayName": "Block legacy",
    "state": "enabled",
    "conditions": {
        "users": {"includeUsers": ["All"], "excludeUsers": ["mystery-admin"]},
        "clientAppTypes": ["exchangeActiveSync", "other"],
    },
    "grantControls": {"builtInControls": ["block"]},
}


def test_priv_gaps_unjustified_exclusion_still_gap() -> None:
    """An exclusion without break-glass rationale must not clear the gap.

    Both protections exist, but both exclude a principal that the assessment
    profile never justifies -> the check must not claim OK.
    """
    result = evaluate_ca_priv_gaps(
        _check("id-ca-priv-gaps"),
        {
            "ca_policies": [_MFA_ALL, _LEGACY_BLOCK],
            "role_assignments": [
                {"principalId": "admin-1", "roleDefinitionId": GA_ROLE},
            ],
            "break_glass_principal_ids": [],
        },
    )
    assert result.status == FindingStatus.GAP
    issues = result.evidence["unjustified_exclusion_issues"]
    assert issues
    assert "mystery-admin" in issues[0]["unjustified_exclusions"]


def test_priv_gaps_justified_break_glass_exclusion_is_ok() -> None:
    mfa = dict(_MFA_ALL)
    mfa["conditions"] = {
        "users": {"includeUsers": ["All"], "excludeUsers": ["break-glass-1"]},
        "clientAppTypes": ["all"],
    }
    legacy = dict(_LEGACY_BLOCK)
    legacy["conditions"] = {
        "users": {"includeUsers": ["All"], "excludeUsers": ["break-glass-1"]},
        "clientAppTypes": ["exchangeActiveSync", "other"],
    }
    result = evaluate_ca_priv_gaps(
        _check("id-ca-priv-gaps"),
        {
            "ca_policies": [mfa, legacy],
            "role_assignments": [
                {"principalId": "admin-1", "roleDefinitionId": GA_ROLE},
            ],
            "break_glass_principal_ids": ["break-glass-1"],
        },
    )
    assert result.status == FindingStatus.OK
    assert result.exposure_class == ExposureClass.NONE
