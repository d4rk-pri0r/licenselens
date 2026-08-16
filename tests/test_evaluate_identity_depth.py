"""Unit tests for the t16 identity-depth checks (PIM activation, access review
scope, number matching, cross-tenant MFA trust, workload identity protection)."""

from __future__ import annotations

from licenselens.collectors.access_reviews import (
    collect_access_review_definitions,
    collect_access_review_instances,
)
from licenselens.collectors.risky_service_principals import (
    collect_risky_service_principals,
)
from licenselens.engine.evaluate import (
    evaluate_access_reviews_scope,
    evaluate_auth_number_matching,
    evaluate_cross_tenant_mfa_trust,
    evaluate_identity_protection_workload,
    evaluate_pim_activation_controls,
)
from licenselens.models import CheckDefinition, FindingStatus, Workload
from tests.fake_clients import FakeGraphClient

GA = "62e90394-69f5-4237-9190-012177145e10"


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=Workload.IDENTITY)


def _rule(type_name: str, rule_id: str, **fields: object) -> dict:
    return {"@odata.type": f"#microsoft.graph.{type_name}", "id": rule_id, **fields}


# -- id-pim-activation-controls ----------------------------------------------


def _pim_bundle(*rules: dict) -> dict:
    return {
        "policies": [{"id": "policy-ga", "displayName": "DirectoryRole", "rules": list(rules)}],
        "assignments": [
            {
                "id": "assign-ga",
                "policyId": "policy-ga",
                "roleDefinitionId": GA,
                "scopeId": "/",
                "scopeType": "DirectoryRole",
            }
        ],
    }


def _full_activation_rules() -> list[dict]:
    return [
        _rule(
            "unifiedRoleManagementPolicyExpirationRule",
            "Expiration_EndUser_Activation",
            isExpirationRequired=True,
            maximumDuration="PT4H",
        ),
        _rule(
            "unifiedRoleManagementPolicyAuthenticationContextRule",
            "AuthenticationContext_EndUser_Activation",
            isEnabled=True,
            claimValue="c1",
        ),
        _rule(
            "unifiedRoleManagementPolicyEnablementRule",
            "Enablement_EndUser_Activation",
            enabledRules=["Justification"],
        ),
    ]


def test_pim_activation_controls_ok_when_all_guardrails_present():
    result = evaluate_pim_activation_controls(
        _check("id-pim-activation-controls"),
        {"pim_policies_bundle": _pim_bundle(*_full_activation_rules())},
    )
    assert result.status == FindingStatus.OK
    assert result.evidence["activation_duration_capped"] is True
    assert result.evidence["auth_context_required"] is True
    assert result.evidence["justification_required"] is True


def test_pim_activation_controls_gap_when_guardrails_missing():
    weak = _pim_bundle(
        _rule(
            "unifiedRoleManagementPolicyExpirationRule",
            "Expiration_EndUser_Activation",
            isExpirationRequired=False,
            maximumDuration="PT0S",
        )
    )
    result = evaluate_pim_activation_controls(
        _check("id-pim-activation-controls"), {"pim_policies_bundle": weak}
    )
    assert result.status == FindingStatus.GAP
    assert result.evidence["activation_duration_capped"] is False
    assert result.evidence["justification_required"] is False


def test_pim_activation_controls_gap_when_duration_over_8_hours():
    over = _pim_bundle(
        *_full_activation_rules(),
        _rule(
            "unifiedRoleManagementPolicyExpirationRule",
            "Expiration_EndUser_Activation_Second",
            isExpirationRequired=True,
            maximumDuration="PT24H",
        ),
    )
    result = evaluate_pim_activation_controls(
        _check("id-pim-activation-controls"), {"pim_policies_bundle": over}
    )
    assert result.status == FindingStatus.GAP


def test_pim_activation_controls_partial_when_no_rules():
    result = evaluate_pim_activation_controls(
        _check("id-pim-activation-controls"),
        {"pim_policies_bundle": {"policies": [], "assignments": []}},
    )
    assert result.status == FindingStatus.PARTIAL


def test_pim_activation_controls_error_on_collection_failure():
    result = evaluate_pim_activation_controls(
        _check("id-pim-activation-controls"),
        {"pim_policies_bundle_error": "403 denied"},
    )
    assert result.status == FindingStatus.ERROR


# -- id-access-reviews-scope -------------------------------------------------


def _privileged_recurring_definition() -> dict:
    return {
        "id": "rev-1",
        "displayName": "Quarterly Global Admin review",
        "scope": {
            "principalScopes": [
                {"query": "/roleManagement/directory/roleAssignments", "queryType": "AllPrincipals"}
            ]
        },
        "settings": {"recurrence": {"range": {"type": "noEnd"}}},
    }


def test_access_reviews_scope_ok_when_privileged_recurring_completed_round():
    result = evaluate_access_reviews_scope(
        _check("id-access-reviews-scope"),
        {
            "access_review_definitions": [_privileged_recurring_definition()],
            "access_review_instances": [
                {"id": "rev-1", "instances": [{"id": "i1", "status": "Completed"}]}
            ],
        },
    )
    assert result.status == FindingStatus.OK
    assert result.evidence["definitions_with_completed_rounds"] == ["rev-1"]


def test_access_reviews_scope_gap_when_no_privileged_scope():
    non_priv = _privileged_recurring_definition()
    non_priv["displayName"] = "Guest users quarterly"
    non_priv["scope"] = {"principalScopes": [{"query": "/users?$filter=userType eq 'Guest'"}]}
    result = evaluate_access_reviews_scope(
        _check("id-access-reviews-scope"),
        {
            "access_review_definitions": [non_priv],
            "access_review_instances": [],
        },
    )
    assert result.status == FindingStatus.GAP


def test_access_reviews_scope_gap_when_review_never_ran():
    result = evaluate_access_reviews_scope(
        _check("id-access-reviews-scope"),
        {
            "access_review_definitions": [_privileged_recurring_definition()],
            "access_review_instances": [{"id": "rev-1", "instances": []}],
        },
    )
    assert result.status == FindingStatus.GAP


def test_access_reviews_scope_partial_when_round_not_completed():
    result = evaluate_access_reviews_scope(
        _check("id-access-reviews-scope"),
        {
            "access_review_definitions": [_privileged_recurring_definition()],
            "access_review_instances": [
                {"id": "rev-1", "instances": [{"id": "i1", "status": "InProgress"}]}
            ],
        },
    )
    assert result.status == FindingStatus.PARTIAL


def test_access_reviews_scope_gap_when_no_definitions():
    result = evaluate_access_reviews_scope(
        _check("id-access-reviews-scope"),
        {"access_review_definitions": [], "access_review_instances": []},
    )
    assert result.status == FindingStatus.GAP


# -- id-number-matching ------------------------------------------------------


def _auth_bundle(number_state: str | None, authenticator_state: str = "enabled") -> dict:
    feature = {}
    if number_state is not None:
        feature["numberMatchingRequiredState"] = {"state": number_state}
    return {
        "auth_methods_bundle": {
            "configurations": [
                {
                    "id": "microsoftAuthenticator",
                    "state": authenticator_state,
                    "featureSettings": feature,
                }
            ]
        }
    }


def test_number_matching_ok_when_enabled():
    result = evaluate_auth_number_matching(_check("id-number-matching"), _auth_bundle("enabled"))
    assert result.status == FindingStatus.OK


def test_number_matching_ok_when_tenant_default():
    result = evaluate_auth_number_matching(_check("id-number-matching"), _auth_bundle("default"))
    assert result.status == FindingStatus.OK


def test_number_matching_gap_when_disabled():
    result = evaluate_auth_number_matching(_check("id-number-matching"), _auth_bundle("disabled"))
    assert result.status == FindingStatus.GAP


def test_number_matching_partial_when_setting_missing():
    result = evaluate_auth_number_matching(_check("id-number-matching"), _auth_bundle(None))
    assert result.status == FindingStatus.PARTIAL


def test_number_matching_partial_when_authenticator_absent():
    result = evaluate_auth_number_matching(
        _check("id-number-matching"), {"auth_methods_bundle": {"configurations": []}}
    )
    assert result.status == FindingStatus.PARTIAL


# -- id-cross-tenant-mfa-trust -----------------------------------------------


def _guests_bundle(inbound_accepted: bool | None, *, outbound_accepted: bool | None = None) -> dict:
    default: dict = {}
    if inbound_accepted is not None:
        default["b2bCollaborationInbound"] = {
            "trustSettings": {"inboundTrust": {"isMfaAccepted": inbound_accepted}}
        }
    if outbound_accepted is not None:
        default["b2bCollaborationOutbound"] = {
            "trustSettings": {"outboundTrust": {"isMfaAccepted": outbound_accepted}}
        }
    return {"guests_bundle": {"default": default, "partners": []}}


def test_cross_tenant_mfa_trust_gap_when_inbound_default_trusts():
    result = evaluate_cross_tenant_mfa_trust(
        _check("id-cross-tenant-mfa-trust"), _guests_bundle(True)
    )
    assert result.status == FindingStatus.GAP
    assert result.evidence["inbound_mfa_trust_default"] is True


def test_cross_tenant_mfa_trust_ok_when_inbound_disabled():
    result = evaluate_cross_tenant_mfa_trust(
        _check("id-cross-tenant-mfa-trust"), _guests_bundle(False, outbound_accepted=True)
    )
    assert result.status == FindingStatus.OK


def test_cross_tenant_mfa_trust_ok_with_explicit_partner_trust():
    bundle = _guests_bundle(False)
    bundle["guests_bundle"]["partners"] = [
        {"tenantId": "t1", "inboundTrust": {"isMfaAccepted": True}}
    ]
    result = evaluate_cross_tenant_mfa_trust(_check("id-cross-tenant-mfa-trust"), bundle)
    assert result.status == FindingStatus.OK
    assert result.evidence["partner_inbound_mfa_trust_count"] == 1


def test_cross_tenant_mfa_trust_partial_when_setting_missing():
    result = evaluate_cross_tenant_mfa_trust(
        _check("id-cross-tenant-mfa-trust"), _guests_bundle(None)
    )
    assert result.status == FindingStatus.PARTIAL


def test_cross_tenant_mfa_trust_error_on_collection_failure():
    result = evaluate_cross_tenant_mfa_trust(
        _check("id-cross-tenant-mfa-trust"), {"guests_bundle_error": "403 denied"}
    )
    assert result.status == FindingStatus.ERROR


# -- id-identity-protection-workload -----------------------------------------


def _risky_sp(risk_state: str, name: str = "Compromised App") -> dict:
    return {
        "id": "sp-1",
        "displayName": name,
        "appId": "b55552fe-a272-4b56-990b-95038d917878",
        "riskState": risk_state,
        "riskLevel": "high",
    }


def test_identity_protection_workload_ok_when_no_risky_sps():
    result = evaluate_identity_protection_workload(
        _check("id-identity-protection-workload"),
        {"risky_service_principals": []},
    )
    assert result.status == FindingStatus.OK
    assert result.evidence["risky_service_principal_count"] == 0


def test_identity_protection_workload_gap_when_confirmed_compromised():
    result = evaluate_identity_protection_workload(
        _check("id-identity-protection-workload"),
        {"risky_service_principals": [_risky_sp("confirmedCompromised")]},
    )
    assert result.status == FindingStatus.GAP
    assert result.evidence["compromised_service_principal_count"] == 1


def test_identity_protection_workload_ok_when_risks_dismissed():
    result = evaluate_identity_protection_workload(
        _check("id-identity-protection-workload"),
        {"risky_service_principals": [_risky_sp("dismissed", "Clean now")]},
    )
    assert result.status == FindingStatus.OK


def test_identity_protection_workload_partial_when_unknown_risk_state():
    result = evaluate_identity_protection_workload(
        _check("id-identity-protection-workload"),
        {"risky_service_principals": [_risky_sp("weirdState")]},
    )
    assert result.status == FindingStatus.PARTIAL


def test_identity_protection_workload_partial_when_endpoint_unavailable():
    result = evaluate_identity_protection_workload(
        _check("id-identity-protection-workload"),
        {"risky_service_principals_error": "404 not found"},
    )
    assert result.status == FindingStatus.PARTIAL


def test_identity_protection_workload_error_when_permission_denied():
    result = evaluate_identity_protection_workload(
        _check("id-identity-protection-workload"),
        {"risky_service_principals_error": "403 Forbidden"},
    )
    assert result.status == FindingStatus.ERROR


# -- collectors --------------------------------------------------------------


def test_collect_risky_service_principals_uses_v1_path():
    fake = FakeGraphClient()
    fake.register_list(
        "/identityProtection/riskyServicePrincipals",
        lambda _path, _params: {"value": [_risky_sp("atRisk", "Live")]},
    )
    items = collect_risky_service_principals(fake)
    assert items[0]["riskState"] == "atRisk"


def test_collect_access_review_instances_expands_instances():
    seen: dict[str, object] = {}

    def handler(_path: str, params: dict | None) -> dict:
        seen["params"] = params
        return {"value": [{"id": "rev-1", "instances": [{"id": "i1", "status": "Completed"}]}]}

    fake = FakeGraphClient()
    fake.register_list("/identityGovernance/accessReviews/definitions", handler)
    rows = collect_access_review_instances(fake)
    assert rows[0]["instances"][0]["status"] == "Completed"
    assert seen["params"] == {"$expand": "instances($top=3)"}

    plain = collect_access_review_definitions(fake)
    assert plain[0]["id"] == "rev-1"
