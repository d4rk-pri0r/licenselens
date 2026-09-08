"""TV-1 acceptance matrix: matched endpoint populations through real reconcile().

Binding contract (audit/trust-and-validation.md, TV-1):

- ``endpoint-enrollment-coverage``: numerator = ``entra_active ∩ intune_managed``,
  denominator = ``entra_active`` (join on Entra deviceId ≡ Intune azureADDeviceId).
- ``mde-onboard-gap``: numerator = ``intune_active ∩ mde_active``, denominator =
  ``intune_active`` (join on Intune azureADDeviceId ≡ MDE aadDeviceId).
- Disjoint inventories must land GAP "0 of N", never OK.
- Proxy/leverage, unresolved-empty, truncated, duplicate, and unmatched-id
  behaviours are pinned below.

Every case (except case 7, whose input is the literal runtime "unavailable"
envelope) builds its ``device_reconciliation`` from a real ``reconcile()``
call and feeds it through BOTH evaluators.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from licenselens.collectors.device_reconcile import reconcile
from licenselens.evaluators.defender_endpoint import evaluate_mde_onboard_gap
from licenselens.evaluators.endpoint_intune_enrollment import (
    evaluate_endpoint_enrollment_coverage,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus, Workload

NOW = datetime(2026, 9, 7, tzinfo=UTC)
RECENT = (NOW - timedelta(days=1)).isoformat().replace("+00:00", "Z")
STALE = (NOW - timedelta(days=60)).isoformat().replace("+00:00", "Z")

TEN = [f"device-{i:02d}-0000-4000-8000-000000000000" for i in range(10)]
THREE = TEN[:3]


def _guid(i: int) -> str:
    return f"device-{i:02d}-0000-4000-8000-000000000000"


def _mde_check() -> CheckDefinition:
    return CheckDefinition(id="mde-onboard-gap", title="mde", workload=Workload.DEFENDER)


def _enroll_check() -> CheckDefinition:
    return CheckDefinition(
        id="endpoint-enrollment-coverage", title="enroll", workload=Workload.ENDPOINT
    )


def _build(
    *,
    entra_ids: list[str],
    intune_ids: list[str],
    mde_ids: list[str],
    intune_stale: set[str] | None = None,
    mde_stale: set[str] | None = None,
    intune_extra: list[dict[str, Any]] | None = None,
    mde_extra: list[dict[str, Any]] | None = None,
    intune_truncated: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Build inventories, run the real reconcile(), return (recon, intune, mde)."""
    entra = {
        "devices": [
            {
                "deviceId": did,
                "accountEnabled": True,
                "approximateLastSignInDateTime": RECENT,
            }
            for did in entra_ids
        ],
        "truncated": False,
    }
    intune_rows = [
        {
            "azureADDeviceId": did,
            "lastSyncDateTime": STALE if did in (intune_stale or set()) else RECENT,
        }
        for did in intune_ids
    ] + list(intune_extra or [])
    mde_rows = [
        {
            "aadDeviceId": did,
            "onboardingStatus": "Onboarded",
            "lastSeen": STALE if did in (mde_stale or set()) else RECENT,
        }
        for did in mde_ids
    ] + list(mde_extra or [])
    intune = {"managed_devices": intune_rows, "truncated": intune_truncated}
    mde = {"machines": mde_rows, "truncated": False}
    recon = reconcile(entra, intune, mde, now=NOW)
    return recon, intune, mde


def _mde_eval(recon: dict[str, Any], mde: dict[str, Any]):
    onboarded_total = sum(
        1
        for row in mde.get("machines") or []
        if isinstance(row, dict) and str(row.get("onboardingStatus") or "") == "Onboarded"
    )
    return evaluate_mde_onboard_gap(
        _mde_check(),
        {
            "mde_summary": {"onboarded_machines": onboarded_total, "truncated": False},
            "device_reconciliation": recon,
        },
    )


def _enroll_eval(recon: dict[str, Any], intune: dict[str, Any]):
    return evaluate_endpoint_enrollment_coverage(
        _enroll_check(),
        {
            "intune_bundle": {
                "managed_devices": list(intune.get("managed_devices") or []),
                "truncated": False,
            },
            "device_reconciliation": recon,
        },
    )


# Case 1 — fully matched (positive control).


def test_case_1_fully_matched_both_ok() -> None:
    recon, intune, mde = _build(entra_ids=TEN, intune_ids=TEN, mde_ids=TEN)
    assert recon["entra_active"] == 10
    assert recon["intune_active"] == 10
    assert recon["intune_matched_mde"] == 10
    assert recon["entra_matched_intune"] == 10
    assert recon["unmatched_ids"] == 0

    mde_result = _mde_eval(recon, mde)
    assert mde_result.status is FindingStatus.OK
    assert "10 of 10" in (mde_result.summary or "")
    assert mde_result.evidence["matched_devices"] == 10
    assert mde_result.evidence["coverage_ratio"] == 1.0

    enroll_result = _enroll_eval(recon, intune)
    assert enroll_result.status is FindingStatus.OK
    assert "10 of 10" in (enroll_result.summary or "")
    assert enroll_result.evidence["matched_devices"] == 10
    assert enroll_result.evidence["coverage_ratio"] == 1.0


# Case 2 — partly overlapping: one verdict PARTIAL, one GAP, exact "x of y".


def test_case_2_partly_overlapping_exact_counts() -> None:
    # 10 Entra, 8 of them in Intune, 3 of those 8 in MDE.
    recon, intune, mde = _build(entra_ids=TEN, intune_ids=TEN[:8], mde_ids=TEN[:3])
    assert recon["entra_matched_intune"] == 8
    assert recon["intune_matched_mde"] == 3

    enroll_result = _enroll_eval(recon, intune)
    assert enroll_result.status is FindingStatus.PARTIAL
    assert "8 of 10 eligible Entra device(s) matched as managed" in (enroll_result.summary or "")
    assert enroll_result.evidence["coverage_ratio"] == 0.8

    mde_result = _mde_eval(recon, mde)
    assert mde_result.status is FindingStatus.GAP
    summary = mde_result.summary or ""
    assert "3 of 8 eligible Intune-managed device(s) matched as onboarded" in summary
    assert mde_result.evidence["coverage_ratio"] == 0.375


# Case 3 — entirely disjoint (the evaluation's exact reproduction).


def test_case_3_disjoint_populations_are_gap_never_ok() -> None:
    recon, intune, mde = _build(
        entra_ids=[f"entra-{i}" for i in range(10)],
        intune_ids=[f"intune-{i}" for i in range(10)],
        mde_ids=[f"mde-{i}" for i in range(10)],
    )
    assert recon["mde_coverage_of_intune"] == 0.0
    assert recon["intune_coverage_of_entra"] == 0.0

    mde_result = _mde_eval(recon, mde)
    assert mde_result.status is FindingStatus.GAP
    assert "0 of 10" in (mde_result.summary or "")
    assert mde_result.evidence["matched_devices"] == 0
    assert mde_result.evidence["coverage_ratio"] == 0.0
    assert mde_result.evidence["observed_onboarded_total"] == 10
    assert mde_result.status is not FindingStatus.OK

    enroll_result = _enroll_eval(recon, intune)
    assert enroll_result.status is FindingStatus.GAP
    assert "0 of 10" in (enroll_result.summary or "")
    assert enroll_result.evidence["matched_devices"] == 0
    assert enroll_result.evidence["coverage_ratio"] == 0.0
    assert enroll_result.status is not FindingStatus.OK


# Case 4 — duplicate rows must not inflate counts (set semantics).


def test_case_4_duplicate_rows_do_not_inflate() -> None:
    recon, intune, mde = _build(entra_ids=TEN, intune_ids=TEN + TEN, mde_ids=TEN + TEN)
    assert recon["intune_active"] == 10
    assert recon["intune_matched_mde"] == 10
    assert recon["entra_matched_intune"] == 10

    mde_result = _mde_eval(recon, mde)
    assert mde_result.status is FindingStatus.OK
    assert "10 of 10" in (mde_result.summary or "")
    assert mde_result.evidence["matched_devices"] == 10
    assert mde_result.evidence["observed_onboarded_total"] == 20

    enroll_result = _enroll_eval(recon, intune)
    assert enroll_result.status is FindingStatus.OK
    assert "10 of 10" in (enroll_result.summary or "")
    assert enroll_result.evidence["matched_devices"] == 10
    assert enroll_result.evidence["managed_device_count"] == 20


# Case 5 — stale Intune sync excluded from the MDE denominator; stale MDE
# lastSeen excluded from the MDE numerator.


def test_case_5_stale_rows_excluded() -> None:
    a, b = _guid(90), _guid(91)
    # A syncs to Intune 60d ago (excluded from intune_active); B was last seen
    # by MDE 60d ago (excluded from mde_active). The join therefore empties.
    recon, intune, mde = _build(
        entra_ids=[a, b],
        intune_ids=[a, b],
        mde_ids=[a, b],
        intune_stale={a},
        mde_stale={b},
    )
    assert recon["intune_active"] == 1  # stale Intune row excluded
    assert recon["mde_active"] == 1  # stale MDE row excluded
    assert recon["intune_matched_mde"] == 0

    mde_result = _mde_eval(recon, mde)
    assert mde_result.status is FindingStatus.GAP
    assert "0 of 1" in (mde_result.summary or "")
    assert mde_result.evidence["matched_devices"] == 0

    # Enrollment joins entra_active with intune_managed (no sync-window filter
    # on the managed set), so both devices still count as managed.
    enroll_result = _enroll_eval(recon, intune)
    assert enroll_result.status is FindingStatus.OK
    assert "2 of 2" in (enroll_result.summary or "")
    assert recon["entra_matched_intune"] == 2


# Case 6 — rows without a usable join id are excluded and counted.


def test_case_6_unmatched_ids_excluded_and_surfaced() -> None:
    recon, intune, mde = _build(
        entra_ids=THREE,
        intune_ids=THREE,
        mde_ids=THREE,
        intune_extra=[{"azureADDeviceId": None, "lastSyncDateTime": RECENT}],
        mde_extra=[{"aadDeviceId": "", "onboardingStatus": "Onboarded", "lastSeen": RECENT}],
    )
    assert recon["unmatched_ids"] == 2
    assert recon["intune_active"] == 3
    assert recon["intune_matched_mde"] == 3

    mde_result = _mde_eval(recon, mde)
    assert mde_result.status is FindingStatus.OK
    assert "3 of 3" in (mde_result.summary or "")
    assert mde_result.evidence["unmatched_ids"] == 2

    enroll_result = _enroll_eval(recon, intune)
    assert enroll_result.status is FindingStatus.OK
    assert "3 of 3" in (enroll_result.summary or "")
    assert enroll_result.evidence["unmatched_ids"] == 2


# Case 7 — reconciliation unavailable: existing proxy path, never OK.


def test_case_7_reconciliation_unavailable_is_proxy_partial() -> None:
    mde_result = evaluate_mde_onboard_gap(
        _mde_check(),
        {
            "mde_summary": {
                "onboarded_machines": 95,
                "licensed_units": 100,
                "truncated": False,
            },
            "device_reconciliation": {"available": False},
        },
    )
    assert mde_result.status is FindingStatus.PARTIAL
    assert mde_result.status is not FindingStatus.OK
    assert mde_result.evidence.get("proxy") is True
    assert "denominator_source" not in mde_result.evidence

    enroll_result = evaluate_endpoint_enrollment_coverage(
        _enroll_check(),
        {
            "intune_bundle": {
                "managed_devices": [{"id": "d1"}, {"id": "d2"}],
                "licensed_units": 100,
                "truncated": False,
            },
            "device_reconciliation": {"available": False},
        },
    )
    assert enroll_result.status is FindingStatus.PARTIAL
    assert enroll_result.status is not FindingStatus.OK
    assert enroll_result.evidence.get("proxy") is True


# Case 8 — empty eligible population: unresolved PARTIAL, never OK, no crash.


def test_case_8a_entra_empty_enrollment_unresolved_mde_ok() -> None:
    recon, intune, mde = _build(entra_ids=[], intune_ids=THREE, mde_ids=THREE)
    assert recon["entra_active"] == 0

    enroll_result = _enroll_eval(recon, intune)
    assert enroll_result.status is FindingStatus.PARTIAL
    assert enroll_result.status is not FindingStatus.OK
    assert "unresolved" in (enroll_result.summary or "")

    mde_result = _mde_eval(recon, mde)
    assert mde_result.status is FindingStatus.OK
    assert "3 of 3" in (mde_result.summary or "")


def test_case_8b_intune_empty_mde_unresolved_enrollment_gap() -> None:
    recon, intune, mde = _build(entra_ids=THREE, intune_ids=[], mde_ids=THREE)
    assert recon["intune_active"] == 0

    mde_result = _mde_eval(recon, mde)
    assert mde_result.status is FindingStatus.PARTIAL
    assert mde_result.status is not FindingStatus.OK
    assert "could not be computed" in (mde_result.summary or "")

    enroll_result = _enroll_eval(recon, intune)
    assert enroll_result.status is FindingStatus.GAP
    assert "0 of 3" in (enroll_result.summary or "")


# Case 9 — truncated inventory: ratio still computed, never OK, MEDIUM confidence.


def test_case_9_truncated_never_ok_medium_confidence() -> None:
    recon, intune, mde = _build(
        entra_ids=TEN,
        intune_ids=TEN,
        mde_ids=TEN,
        intune_truncated=True,
    )
    assert recon["truncated"] is True

    mde_result = _mde_eval(recon, mde)
    assert mde_result.status is FindingStatus.PARTIAL
    assert mde_result.status is not FindingStatus.OK
    assert mde_result.confidence is Confidence.MEDIUM
    assert mde_result.evidence["coverage_ratio"] == 1.0
    assert mde_result.evidence["matched_devices"] == 10

    enroll_result = _enroll_eval(recon, intune)
    assert enroll_result.status is FindingStatus.PARTIAL
    assert enroll_result.status is not FindingStatus.OK
    assert enroll_result.confidence is Confidence.MEDIUM
    assert enroll_result.evidence["coverage_ratio"] == 1.0
