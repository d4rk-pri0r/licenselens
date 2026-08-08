"""Unit tests for new identity evaluators (security defaults + access reviews)."""

from licenselens.engine.evaluate import (
    evaluate_access_reviews_unused,
    evaluate_security_defaults_on,
)
from licenselens.models import CheckDefinition, FindingStatus, Workload


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


def test_security_defaults_off_is_ok():
    result = evaluate_security_defaults_on(
        _check("id-security-defaults-on"),
        {"security_defaults_policy": {"id": "p", "isEnabled": False}},
    )
    assert result.status == FindingStatus.OK


def test_security_defaults_missing_data():
    result = evaluate_security_defaults_on(
        _check("id-security-defaults-on"),
        {"security_defaults_policy": {}},
    )
    assert result.status == FindingStatus.OK  # absent = off = OK


# -- Access reviews -----------------------------------------------------------


def test_access_reviews_none_is_gap():
    result = evaluate_access_reviews_unused(
        _check("id-access-reviews-unused"),
        {"access_review_definitions": []},
    )
    assert result.status == FindingStatus.GAP
    assert result.evidence["definition_count"] == 0


def test_access_reviews_some_is_ok():
    result = evaluate_access_reviews_unused(
        _check("id-access-reviews-unused"),
        {
            "access_review_definitions": [
                {"id": "ar-1", "displayName": "Guest review"},
                {"id": "ar-2", "displayName": "Admin review"},
            ]
        },
    )
    assert result.status == FindingStatus.OK
    assert result.evidence["definition_count"] == 2
    assert "ar-1" in str(result.evidence["definition_ids"])
