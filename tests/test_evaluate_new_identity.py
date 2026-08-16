"""Unit tests for new identity evaluators (security defaults + access reviews)."""

from licenselens.engine.evaluate import (
    evaluate_access_reviews_unused,
    evaluate_ca_priv_gaps,
    evaluate_security_defaults_on,
)
from licenselens.models import CheckDefinition, ExposureClass, FindingStatus, Workload


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=Workload.IDENTITY)


# -- Security defaults --------------------------------------------------------


def test_security_defaults_on_is_gap():
    result = evaluate_security_defaults_on(
        _check("id-security-defaults-on"),
        {"security_defaults_policy": {"id": "p", "isEnabled": True}},
    )
    assert result.status == FindingStatus.GAP
    assert result.evidence["security_defaults_enabled"] is True


def test_security_defaults_on_records_baseline_protection():
    result = evaluate_security_defaults_on(
        _check("id-security-defaults-on"),
        {"security_defaults_policy": {"id": "p", "isEnabled": True}},
    )
    assert result.status == FindingStatus.GAP
    assert result.evidence["baseline_protections_active"] is True
    assert result.evidence["conditional_access_customization_unused"] is True


def test_security_defaults_off_without_ca_evidence_is_partial():
    result = evaluate_security_defaults_on(
        _check("id-security-defaults-on"),
        {"security_defaults_policy": {"id": "p", "isEnabled": False}},
    )
    assert result.status == FindingStatus.PARTIAL


def test_security_defaults_missing_data():
    result = evaluate_security_defaults_on(
        _check("id-security-defaults-on"),
        {"security_defaults_policy": {}},
    )
    assert result.status == FindingStatus.PARTIAL  # absent = off, CA unverified = PARTIAL


def test_security_defaults_collection_error_returns_error():
    """BUG 1: when Graph returns 403 for Security Defaults, evaluation must ERROR."""
    result = evaluate_security_defaults_on(
        _check("id-security-defaults-on"),
        {
            "security_defaults_policy": {},
            "security_defaults_policy_error": "403 Forbidden",
        },
    )
    assert result.status == FindingStatus.ERROR


def test_security_defaults_off_does_not_claim_ca_customization():
    """BUG 2: when SD is off, we cannot assert CA customization is unused."""
    result = evaluate_security_defaults_on(
        _check("id-security-defaults-on"),
        {"security_defaults_policy": {"id": "p", "isEnabled": False}},
    )
    assert result.status != FindingStatus.OK
    assert result.evidence["conditional_access_customization_unused"] is None


# -- CA + Security Defaults interaction (BUG 2) --------------------------------


def test_ca_sd_enabled_blocks_legacy_exposure():
    """When SD is enabled, legacy auth is blocked — no exposure even with no CA."""
    evidence = {
        "ca_policies": [],
        "role_assignments": [],
        "security_defaults_policy": {"isEnabled": True},
    }
    result = evaluate_ca_priv_gaps(
        _check("id-ca-priv-gaps"),
        evidence,
    )
    assert result.exposure_class == ExposureClass.NONE
    assert "legacy_auth_broadly_allowed" not in result.evidence.get("exposure_flags", [])


# -- Access reviews -----------------------------------------------------------


def test_access_reviews_none_is_gap():
    result = evaluate_access_reviews_unused(
        _check("id-access-reviews-unused"),
        {"access_review_definitions": []},
    )
    assert result.status == FindingStatus.GAP
    assert result.evidence["definition_count"] == 0


def test_access_reviews_some_without_privileged_recurring_scope_is_partial():
    result = evaluate_access_reviews_unused(
        _check("id-access-reviews-unused"),
        {
            "access_review_definitions": [
                {"id": "ar-1", "displayName": "Guest review"},
                {"id": "ar-2", "displayName": "Admin review"},
            ]
        },
    )
    assert result.status == FindingStatus.PARTIAL
    assert result.evidence["definition_count"] == 2
    assert "ar-1" in str(result.evidence["definition_ids"])


def test_access_reviews_collection_error_returns_error():
    """BUG 3: when Graph returns 403, evaluation must ERROR — not false GAP."""
    result = evaluate_access_reviews_unused(
        _check("id-access-reviews-unused"),
        {
            "access_review_definitions": [],
            "access_review_definitions_error": "403 Forbidden",
        },
    )
    assert result.status == FindingStatus.ERROR
