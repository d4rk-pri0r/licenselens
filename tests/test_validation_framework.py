"""Validation framework tests (§14): sanitized real-tenant recording + metrics.

Asserts that summary metrics default to zero (never invented), that distinct
check_ids are counted correctly across records, that a check_id cannot appear in
more than one outcome category, and that a record round-trips through JSON.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from licenselens.models import TenantValidationRecord
from licenselens.validation import ValidationMetrics, compute_validation_metrics


def test_empty_metrics_are_all_zero():
    metrics = compute_validation_metrics([])
    assert metrics == ValidationMetrics()
    assert metrics.total_evaluated_findings == 0
    assert metrics.human_confirmed_findings == 0
    assert metrics.rejected_findings == 0
    assert metrics.reclassified_findings == 0
    assert metrics.manual_only_findings == 0
    assert metrics.unknown_findings == 0
    assert metrics.false_negative_discoveries == 0
    assert metrics.false_positive_rate == 0.0
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
    assert metrics.false_positive_rate == 0.5
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


def test_dedup_across_multiple_records_for_confirmed_and_rejected():
    records = [
        TenantValidationRecord(
            confirmed_findings=["id-ca-priv-gaps", "mfa-enabled"],
            rejected_findings=["pur-dlp-not-enforced"],
            raw_finding_count=10,
        ),
        TenantValidationRecord(
            confirmed_findings=["id-ca-priv-gaps", "teams-external-sharing"],
            rejected_findings=["pur-dlp-not-enforced", "mdo-p2-policies-default"],
            raw_finding_count=20,
        ),
    ]
    metrics = compute_validation_metrics(records)
    assert metrics.total_evaluated_findings == 30
    assert metrics.human_confirmed_findings == 3
    assert metrics.rejected_findings == 2
    assert metrics.false_positive_rate == 2 / 3
    assert metrics.validated_tenant_runs == 2


def test_false_positive_rate_is_zero_when_no_confirmed():
    record = TenantValidationRecord(rejected_findings=["pur-dlp-not-enforced"])
    metrics = compute_validation_metrics([record])
    assert metrics.human_confirmed_findings == 0
    assert metrics.rejected_findings == 1
    assert metrics.false_positive_rate == 0.0


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
