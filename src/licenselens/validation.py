"""Real-tenant / practitioner validation metrics.

This module computes honest summary metrics from sanitized
:class:`~licenselens.models.TenantValidationRecord` entries. **No validation
numbers are invented**: unmeasured quantities stay ``None`` or zero until a
real, human-adjudicated observation is recorded.

Units (do not mix them):

- **Unique-check breadth** — distinct ``check_id`` values that have at least
  one qualifying review annotation. Answers "how many checks have been looked
  at?"
- **Per-assessment observations** — a (run, check) pair. The same check
  reviewed in two different recorded runs is two observations. Duplicate
  imports of the same ``record_id`` are not new observations.
- **Adjudicated outcomes** — confirmed or rejected. Unresolved / unreviewed
  annotations (unknown, reclassified, manual-only) are excluded from the
  rejection share.
- **Rejected share** — ``rejected_observations / (confirmed + rejected)``.
  With no adjudicated observations this is ``None`` (unmeasured), never zero.
  It is **not** a statistical false-positive rate: that would need a
  ground-truth negative denominator and a sampling design these records do
  not contain.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel

from licenselens.models import TenantValidationRecord


class ValidationMetrics(BaseModel):
    """Aggregate metrics derived from sanitized validation records."""

    total_evaluated_findings: int = 0
    human_confirmed_findings: int = 0
    rejected_findings: int = 0
    reclassified_findings: int = 0
    manual_only_findings: int = 0
    unknown_findings: int = 0
    false_negative_discoveries: int = 0
    unique_checks_reviewed: int = 0
    confirmed_observations: int = 0
    rejected_observations: int = 0
    adjudicated_observations: int = 0
    rejected_share: float | None = None
    false_positive_rate: float | None = None
    validated_tenant_runs: int = 0
    duplicate_records_ignored: int = 0


def _unique(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in values:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def compute_validation_metrics(
    records: Sequence[TenantValidationRecord],
) -> ValidationMetrics:
    """Compute summary metrics from sanitized validation records.

    Distinct ``record_id`` values are counted once (later duplicates are
    ignored so re-importing a file cannot inflate observations). Records with
    an empty ``record_id`` cannot be de-duplicated and each is treated as a
    distinct run.

    Unique-check breadth counts distinct ``check_id`` values. Observation
    counts sum per-record unique check ids so two runs of the same check are
    two observations. The rejection share is
    ``rejected_observations / adjudicated_observations`` and is ``None`` when
    nothing has been adjudicated.
    """
    confirmed_ids: set[str] = set()
    rejected_ids: set[str] = set()
    reclassified_ids: set[str] = set()
    manual_only_ids: set[str] = set()
    unknown_ids: set[str] = set()
    false_negative_ids: set[str] = set()
    reviewed_ids: set[str] = set()

    confirmed_observations = 0
    rejected_observations = 0
    total_evaluated = 0
    duplicate_ignored = 0
    seen_record_ids: set[str] = set()
    kept_records = 0

    for record in records:
        record_id = (record.record_id or "").strip()
        if record_id:
            if record_id in seen_record_ids:
                duplicate_ignored += 1
                continue
            seen_record_ids.add(record_id)
        kept_records += 1
        total_evaluated += record.raw_finding_count

        confirmed = _unique(record.confirmed_findings)
        rejected = _unique(record.rejected_findings)
        reclassified = _unique(record.reclassified_findings)
        manual_only = _unique(record.manual_only_findings)
        unknown = _unique(record.unknown_findings)
        false_negative = _unique(record.false_negative_discoveries)

        confirmed_ids.update(confirmed)
        rejected_ids.update(rejected)
        reclassified_ids.update(reclassified)
        manual_only_ids.update(manual_only)
        unknown_ids.update(unknown)
        false_negative_ids.update(false_negative)
        reviewed_ids.update(confirmed)
        reviewed_ids.update(rejected)

        confirmed_observations += len(confirmed)
        rejected_observations += len(rejected)

    adjudicated = confirmed_observations + rejected_observations
    rejected_share = (rejected_observations / adjudicated) if adjudicated else None

    return ValidationMetrics(
        total_evaluated_findings=total_evaluated,
        human_confirmed_findings=len(confirmed_ids),
        rejected_findings=len(rejected_ids),
        reclassified_findings=len(reclassified_ids),
        manual_only_findings=len(manual_only_ids),
        unknown_findings=len(unknown_ids),
        false_negative_discoveries=len(false_negative_ids),
        unique_checks_reviewed=len(reviewed_ids),
        confirmed_observations=confirmed_observations,
        rejected_observations=rejected_observations,
        adjudicated_observations=adjudicated,
        rejected_share=rejected_share,
        false_positive_rate=rejected_share,
        validated_tenant_runs=kept_records,
        duplicate_records_ignored=duplicate_ignored,
    )
