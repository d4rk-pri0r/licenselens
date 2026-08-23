"""Uncertainty semantics (§10): fail-closed evidence, absence-of-evidence rules.

Asserts that incomplete/unsupported/unavailable required evidence can never
yield OK or high confidence, and that indirect evaluations cannot be
high-confidence OK.
"""

from __future__ import annotations

from licenselens.evaluators.limitations_policy import (
    apply_required_evidence_policy,
    has_outcome_blocking_limitations,
    limitation_effect,
)
from licenselens.models import (
    Confidence,
    EvaluationMode,
    Finding,
    FindingStatus,
    Severity,
    ValueImpact,
    Workload,
)


def _finding(*, evaluation_mode: EvaluationMode = EvaluationMode.DIRECT) -> Finding:
    return Finding(
        check_id="unc-test",
        title="unc-test",
        workload=Workload.IDENTITY,
        status=FindingStatus.OK,
        severity=Severity.HIGH,
        value_impact=ValueImpact.HIGH,
        summary="ok",
        evaluation_mode=evaluation_mode,
        confidence=Confidence.HIGH,
    )


def test_required_surface_incomplete_demotes_ok_and_high():
    status, confidence = apply_required_evidence_policy(
        status=FindingStatus.OK,
        confidence=Confidence.HIGH,
        limitations=[],
        required_surface_incomplete=True,
    )
    assert status is FindingStatus.PARTIAL
    assert confidence is Confidence.MEDIUM


def test_incomplete_evidence_limitation_demotes_ok():
    status, confidence = apply_required_evidence_policy(
        status=FindingStatus.OK,
        confidence=Confidence.HIGH,
        limitations=["the required surface was not readable; verify in the portal"],
    )
    assert status is FindingStatus.PARTIAL
    assert confidence is Confidence.MEDIUM


def test_outcome_blocking_never_promotes():
    status, confidence = apply_required_evidence_policy(
        status=FindingStatus.GAP,
        confidence=Confidence.LOW,
        limitations=["security alert inventory was truncated"],
    )
    assert status is FindingStatus.GAP
    assert confidence is Confidence.LOW


def test_advisory_limitation_allows_ok():
    status, confidence = apply_required_evidence_policy(
        status=FindingStatus.OK,
        confidence=Confidence.HIGH,
        limitations=["AI agent risk controls vary by cloud and license; treat this as advisory."],
    )
    assert status is FindingStatus.OK
    assert confidence is Confidence.HIGH


def test_proxy_marker_is_outcome_blocking():
    assert limitation_effect("Secure Score proxy; verify in portal") == "outcome_blocking"
    assert has_outcome_blocking_limitations(["Secure Score proxy; verify in portal"])


def test_indirect_evaluation_cannot_be_high_confidence_ok():
    for mode in (
        EvaluationMode.PROXY,
        EvaluationMode.MANUAL,
        EvaluationMode.UNSUPPORTED,
    ):
        try:
            _finding(evaluation_mode=mode)
            raise AssertionError(f"{mode.value} high-confidence OK must be rejected")
        except ValueError:
            pass
    assert _finding(evaluation_mode=EvaluationMode.DIRECT).status is FindingStatus.OK
