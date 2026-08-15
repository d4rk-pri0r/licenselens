"""Determinism tests for app credential evaluators.

The credential lifetime/expiry evaluators must compute ``days`` relative to the
scan's own timestamp (``scanned_at``), not the wall clock, so the pinned dry-run
sample is byte-reproducible across UTC days.
"""

from __future__ import annotations

import datetime as dt

from licenselens.evaluators import identity_apps_credentials as iap
from licenselens.evaluators.identity_apps_credentials import evaluate_app_expiring_credentials
from licenselens.models import CheckDefinition, Workload

_SCAN_AT = "2026-08-13T00:00:00+00:00"
_END = "2024-01-01"


class _FrozenClock:
    """A module-level ``datetime`` shim whose ``now`` is pinned to a fixed instant."""

    def __init__(self, frozen: dt.datetime) -> None:
        self._frozen = frozen

    def now(self, tz: dt.tzinfo | None = None) -> dt.datetime:
        return self._frozen

    def fromisoformat(self, text: str) -> dt.datetime:
        return dt.datetime.fromisoformat(text)


def _check() -> CheckDefinition:
    return CheckDefinition(
        id="id-app-expiring-credentials",
        title="id-app-expiring-credentials",
        workload=Workload.IDENTITY,
    )


def _evidence() -> dict:
    return {
        "scanned_at": _SCAN_AT,
        "applications_bundle": {
            "applications": [
                {
                    "id": "app-1",
                    "displayName": "Legacy Line-of-Business",
                    "passwordCredentials": [{"displayName": "old-secret", "endDateTime": _END}],
                    "keyCredentials": [],
                }
            ]
        },
    }


def test_expiring_credentials_days_uses_scan_timestamp_not_wall_clock(
    monkeypatch,
) -> None:
    evidence = _evidence()

    monkeypatch.setattr(iap, "datetime", _FrozenClock(dt.datetime(2099, 1, 1, tzinfo=dt.UTC)))
    first = evaluate_app_expiring_credentials(_check(), evidence)

    monkeypatch.setattr(iap, "datetime", _FrozenClock(dt.datetime(1999, 1, 1, tzinfo=dt.UTC)))
    second = evaluate_app_expiring_credentials(_check(), evidence)

    assert first.evidence["already_expired"][0]["days"] == "-955"
    assert second.evidence["already_expired"][0]["days"] == "-955"


def test_expiring_credentials_falls_back_to_wall_clock_without_scan_timestamp(
    monkeypatch,
) -> None:
    evidence = _evidence()
    evidence.pop("scanned_at")

    monkeypatch.setattr(iap, "datetime", _FrozenClock(dt.datetime(2026, 8, 13, tzinfo=dt.UTC)))
    result = evaluate_app_expiring_credentials(_check(), evidence)

    assert result.evidence["already_expired"][0]["days"] == "-955"
