"""Validation framework tests: sanitized recording + honest metric units.

Asserts that unmeasured quantities stay None (never invented as zero), that
unique-check breadth is distinct from per-run observations, that duplicate
record_id imports do not inflate counts, and that a record round-trips through
JSON.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from licenselens.models import TenantValidationRecord
from licenselens.validation import ValidationMetrics, compute_validation_metrics


def test_empty_metrics_are_unmeasured():
    metrics = compute_validation_metrics([])
    assert metrics == ValidationMetrics()
    assert metrics.total_evaluated_findings == 0
    assert metrics.human_confirmed_findings == 0
    assert metrics.rejected_findings == 0
    assert metrics.reclassified_findings == 0
    assert metrics.manual_only_findings == 0
    assert metrics.unknown_findings == 0
    assert metrics.false_negative_discoveries == 0
    assert metrics.unique_checks_reviewed == 0
    assert metrics.confirmed_observations == 0
    assert metrics.rejected_observations == 0
    assert metrics.adjudicated_observations == 0
    assert metrics.rejected_share is None
    assert metrics.false_positive_rate is None
    assert metrics.validated_tenant_runs == 0


def test_empty_record_defaults_are_zero():
    record = TenantValidationRecord()
    assert record.tenant_profile == ""
    assert record.license_summary == []
    assert record.raw_finding_count == 0
    assert record.confirmed_findings == []
    assert record.rejected_findings == []


def test_populated_record_yields_expected_distinct_counts():
    record = TenantValidationRecord(
        record_id="val-1",
        tenant_profile="m365-e5",
        license_summary=["E5", "Entra ID P2"],
        scanned_at="2026-08-23T14:30:00Z",
        reviewer="alice@consultancy.example",
        method="real-customer-consented",
        confirmed_findings=["id-ca-priv-gaps", "mfa-enabled"],
        rejected_findings=["pur-dlp-not-enforced"],
        reclassified_findings=["mdo-p2-policies-default"],
        manual_only_findings=["sentinel-workspace-missing"],
        unknown_findings=["exchange-online-archive"],
        false_negative_discoveries=["teams-external-sharing"],
        api_limitations=["sign-in inventory truncated"],
        unexpected_edge_cases=["guest-only tenant"],
        raw_finding_count=42,
    )
    metrics = compute_validation_metrics([record])
    assert metrics.total_evaluated_findings == 42
    assert metrics.human_confirmed_findings == 2
    assert metrics.rejected_findings == 1
    assert metrics.reclassified_findings == 1
    assert metrics.manual_only_findings == 1
    assert metrics.unknown_findings == 1
    assert metrics.false_negative_discoveries == 1
    assert metrics.unique_checks_reviewed == 3
    assert metrics.confirmed_observations == 2
    assert metrics.rejected_observations == 1
    assert metrics.adjudicated_observations == 3
    assert metrics.rejected_share == pytest.approx(1 / 3)
    assert metrics.false_positive_rate == metrics.rejected_share
    assert metrics.validated_tenant_runs == 1


def test_check_id_in_confirmed_and_rejected_raises_value_error():
    with pytest.raises(ValueError):
        TenantValidationRecord(
            confirmed_findings=["id-ca-priv-gaps"],
            rejected_findings=["id-ca-priv-gaps"],
        )


def test_check_id_in_confirmed_and_reclassified_raises_value_error():
    with pytest.raises(ValueError):
        TenantValidationRecord(
            confirmed_findings=["id-ca-priv-gaps"],
            reclassified_findings=["id-ca-priv-gaps"],
        )


def test_duplicate_within_same_category_is_allowed():
    # A check repeated within one category is not an overlap; it is deduped.
    record = TenantValidationRecord(
        confirmed_findings=["id-ca-priv-gaps", "id-ca-priv-gaps"],
    )
    metrics = compute_validation_metrics([record])
    assert metrics.human_confirmed_findings == 1
    assert metrics.confirmed_observations == 1


def test_unique_check_breadth_vs_per_run_observations():
    records = [
        TenantValidationRecord(
            record_id="run-1",
            confirmed_findings=["id-ca-priv-gaps", "mfa-enabled"],
            rejected_findings=["pur-dlp-not-enforced"],
            raw_finding_count=10,
        ),
        TenantValidationRecord(
            record_id="run-2",
            confirmed_findings=["id-ca-priv-gaps", "teams-external-sharing"],
            rejected_findings=["pur-dlp-not-enforced", "mdo-p2-policies-default"],
            raw_finding_count=20,
        ),
    ]
    metrics = compute_validation_metrics(records)
    assert metrics.total_evaluated_findings == 30
    assert metrics.human_confirmed_findings == 3
    assert metrics.rejected_findings == 2
    assert metrics.unique_checks_reviewed == 5
    assert metrics.confirmed_observations == 4
    assert metrics.rejected_observations == 3
    assert metrics.adjudicated_observations == 7
    assert metrics.rejected_share == pytest.approx(3 / 7)
    assert metrics.validated_tenant_runs == 2


def test_all_rejected_is_one_hundred_percent_not_zero():
    record = TenantValidationRecord(
        record_id="all-rej",
        rejected_findings=["a", "b"],
        raw_finding_count=2,
    )
    metrics = compute_validation_metrics([record])
    assert metrics.human_confirmed_findings == 0
    assert metrics.rejected_findings == 2
    assert metrics.rejected_observations == 2
    assert metrics.adjudicated_observations == 2
    assert metrics.rejected_share == pytest.approx(1.0)
    assert metrics.false_positive_rate == pytest.approx(1.0)


def test_two_rejected_one_confirmed_is_two_thirds():
    record = TenantValidationRecord(
        record_id="mixed",
        confirmed_findings=["a"],
        rejected_findings=["b", "c"],
        raw_finding_count=3,
    )
    metrics = compute_validation_metrics([record])
    assert metrics.rejected_share == pytest.approx(2 / 3)
    assert metrics.false_positive_rate == pytest.approx(2 / 3)


def test_repeated_runs_same_check_are_separate_observations():
    records = [
        TenantValidationRecord(
            record_id=str(i),
            confirmed_findings=["a"],
            raw_finding_count=1,
        )
        for i in range(10)
    ]
    metrics = compute_validation_metrics(records)
    assert metrics.human_confirmed_findings == 1
    assert metrics.confirmed_observations == 10
    assert metrics.rejected_share == pytest.approx(0.0)
    assert metrics.validated_tenant_runs == 10


def test_duplicate_record_id_is_not_a_new_observation():
    records = [
        TenantValidationRecord(
            record_id="same",
            confirmed_findings=["a"],
            raw_finding_count=5,
        ),
        TenantValidationRecord(
            record_id="same",
            confirmed_findings=["a", "b"],
            raw_finding_count=9,
        ),
    ]
    metrics = compute_validation_metrics(records)
    assert metrics.validated_tenant_runs == 1
    assert metrics.duplicate_records_ignored == 1
    assert metrics.human_confirmed_findings == 1
    assert metrics.confirmed_observations == 1
    assert metrics.total_evaluated_findings == 5


def test_unresolved_annotations_excluded_from_rejected_share():
    record = TenantValidationRecord(
        record_id="unresolved",
        unknown_findings=["u1"],
        reclassified_findings=["r1"],
        manual_only_findings=["m1"],
        raw_finding_count=3,
    )
    metrics = compute_validation_metrics([record])
    assert metrics.adjudicated_observations == 0
    assert metrics.rejected_share is None
    assert metrics.false_positive_rate is None
    assert metrics.unknown_findings == 1
    assert metrics.unique_checks_reviewed == 0


def test_round_trip_serialize_to_json_and_back():
    record = TenantValidationRecord(
        record_id="val-1",
        tenant_profile="m365-e5",
        license_summary=["E5"],
        scanned_at="2026-08-23T14:30:00Z",
        reviewer="alice@consultancy.example",
        method="controlled-lab",
        confirmed_findings=["id-ca-priv-gaps"],
        rejected_findings=["pur-dlp-not-enforced"],
        raw_finding_count=7,
    )
    data = record.model_dump_json()
    restored = TenantValidationRecord.model_validate_json(data)
    assert restored == record
    assert restored.record_id == "val-1"
    assert restored.confirmed_findings == ["id-ca-priv-gaps"]
    assert restored.raw_finding_count == 7


def test_invalid_overlap_fails_closed_on_parse():
    # Overlap must be rejected even when the record is built from raw JSON.
    with pytest.raises(ValidationError):
        TenantValidationRecord.model_validate(
            {
                "confirmed_findings": ["id-ca-priv-gaps"],
                "unknown_findings": ["id-ca-priv-gaps"],
            }
        )
