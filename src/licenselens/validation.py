"""Real-tenant / practitioner validation metrics (§14).

This module computes honest summary metrics from sanitized
:class:`~licenselens.models.TenantValidationRecord` entries. **No validation
numbers are invented**: every metric defaults to zero until a real,
human-confirmed validation run is recorded.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel

from licenselens.models import TenantValidationRecord


class ValidationMetrics(BaseModel):
    """Aggregate metrics derived from a set of sanitized validation records.

    All counts are derived from the recorded check_ids (deduplicated across
    records) and default to zero when nothing has been recorded.
    """

    total_evaluated_findings: int = 0
    human_confirmed_findings: int = 0
    rejected_findings: int = 0
    reclassified_findings: int = 0
    manual_only_findings: int = 0
    unknown_findings: int = 0
    false_negative_discoveries: int = 0
    false_positive_rate: float = 0.0
    validated_tenant_runs: int = 0


def compute_validation_metrics(
    records: Sequence[TenantValidationRecord],
) -> ValidationMetrics:
    """Compute summary metrics from a sequence of sanitized validation records.

    Distinct check_ids are counted once per category across all records. The
    false-positive rate is ``rejected / confirmed`` and defaults to ``0.0``
    whenever there are no human-confirmed findings (never a fabricated figure).
    """
    confirmed: set[str] = set()
    rejected: set[str] = set()
    reclassified: set[str] = set()
    manual_only: set[str] = set()
    unknown: set[str] = set()
    false_negative: set[str] = set()

    total_evaluated = 0
    for record in records:
        total_evaluated += record.raw_finding_count
        confirmed.update(record.confirmed_findings)
        rejected.update(record.rejected_findings)
        reclassified.update(record.reclassified_findings)
        manual_only.update(record.manual_only_findings)
        unknown.update(record.unknown_findings)
        false_negative.update(record.false_negative_discoveries)

    confirmed_count = len(confirmed)
    rejected_count = len(rejected)
    false_positive_rate = rejected_count / confirmed_count if confirmed_count else 0.0

    return ValidationMetrics(
        total_evaluated_findings=total_evaluated,
        human_confirmed_findings=confirmed_count,
        rejected_findings=rejected_count,
        reclassified_findings=len(reclassified),
        manual_only_findings=len(manual_only),
        unknown_findings=len(unknown),
        false_negative_discoveries=len(false_negative),
        false_positive_rate=false_positive_rate,
        validated_tenant_runs=len(records),
    )
