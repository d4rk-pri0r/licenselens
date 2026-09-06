"""WS4-A: Entra/Intune/MDE device reconciliation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from licenselens.collectors.device_hash import hash_device_label
from licenselens.collectors.device_reconcile import reconcile
from licenselens.evaluators.defender_endpoint import evaluate_mde_onboard_gap
from licenselens.evaluators.endpoint_intune_enrollment import evaluate_endpoint_enrollment_coverage
from licenselens.models import CheckDefinition, Confidence, FindingStatus, Workload

NOW = datetime(2026, 9, 6, tzinfo=UTC)
RECENT = (NOW - timedelta(days=2)).isoformat().replace("+00:00", "Z")
STALE = (NOW - timedelta(days=60)).isoformat().replace("+00:00", "Z")
GUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
GUID_UPPER = GUID.upper()


def _entra(*rows: dict) -> dict:
    return {"devices": list(rows), "truncated": False}


def _intune(*rows: dict) -> dict:
    return {"managed_devices": list(rows), "truncated": False}


def _mde(*rows: dict) -> dict:
    return {"machines": list(rows), "truncated": False}


def test_hash_is_sha256_prefix() -> None:
    assert hash_device_label("host.contoso.com") == hash_device_label("host.contoso.com")
    assert len(hash_device_label("host.contoso.com")) == 12
    assert hash_device_label("") == ""
    assert hash_device_label("host.contoso.com") != "host.contoso.com"


def test_exact_match_join() -> None:
    result = reconcile(
        _entra(
            {
                "deviceId": GUID,
                "accountEnabled": True,
                "approximateLastSignInDateTime": RECENT,
            }
        ),
        _intune({"azureADDeviceId": GUID, "lastSyncDateTime": RECENT}),
        _mde({"aadDeviceId": GUID, "onboardingStatus": "Onboarded", "lastSeen": RECENT}),
        now=NOW,
    )
    assert result["intune_active"] == 1
    assert result["mde_active"] == 1
    assert result["entra_active"] == 1
    assert result["mde_coverage_of_intune"] == 1.0
    assert result["intune_coverage_of_entra"] == 1.0
    assert result["intune_not_onboarded"] == []
    assert result["truncated"] is False


def test_case_insensitive_guid() -> None:
    result = reconcile(
        _entra(
            {
                "deviceId": GUID_UPPER,
                "accountEnabled": True,
                "approximateLastSignInDateTime": RECENT,
            }
        ),
        _intune({"azureADDeviceId": GUID, "lastSyncDateTime": RECENT}),
        _mde({"aadDeviceId": GUID, "onboardingStatus": "Onboarded", "lastSeen": RECENT}),
        now=NOW,
    )
    assert result["mde_coverage_of_intune"] == 1.0


def test_stale_intune_excluded() -> None:
    result = reconcile(
        _entra(),
        _intune({"azureADDeviceId": GUID, "lastSyncDateTime": STALE}),
        _mde({"aadDeviceId": GUID, "onboardingStatus": "Onboarded", "lastSeen": RECENT}),
        now=NOW,
    )
    assert result["intune_active"] == 0
    assert result["mde_coverage_of_intune"] is None


def test_stale_mde_excluded() -> None:
    result = reconcile(
        _entra(),
        _intune({"azureADDeviceId": GUID, "lastSyncDateTime": RECENT}),
        _mde({"aadDeviceId": GUID, "onboardingStatus": "Onboarded", "lastSeen": STALE}),
        now=NOW,
    )
    assert result["mde_active"] == 0
    assert result["intune_not_onboarded"] == [GUID]


def test_disabled_entra_excluded() -> None:
    result = reconcile(
        _entra(
            {
                "deviceId": GUID,
                "accountEnabled": False,
                "approximateLastSignInDateTime": RECENT,
            }
        ),
        _intune(),
        _mde(),
        now=NOW,
    )
    assert result["entra_active"] == 0


def test_missing_ids_skipped() -> None:
    result = reconcile(
        _entra({"deviceId": "", "accountEnabled": True, "approximateLastSignInDateTime": RECENT}),
        _intune({"azureADDeviceId": None, "lastSyncDateTime": RECENT}),
        _mde({"aadDeviceId": "", "onboardingStatus": "Onboarded", "lastSeen": RECENT}),
        now=NOW,
    )
    assert result["intune_active"] == 0
    assert result["mde_active"] == 0
    assert result["entra_active"] == 0


def test_empty_inventories() -> None:
    result = reconcile({}, {}, {}, now=NOW)
    assert result["intune_active"] == 0
    assert result["mde_coverage_of_intune"] is None
    assert result["intune_coverage_of_entra"] is None


def test_intune_not_onboarded() -> None:
    result = reconcile(
        _entra(),
        _intune({"azureADDeviceId": GUID, "lastSyncDateTime": RECENT}),
        _mde(),
        now=NOW,
    )
    assert result["intune_not_onboarded"] == [GUID]
    assert result["mde_coverage_of_intune"] == 0.0


def test_mde_only() -> None:
    result = reconcile(
        _entra(),
        _intune(),
        _mde({"aadDeviceId": GUID, "onboardingStatus": "Onboarded", "lastSeen": RECENT}),
        now=NOW,
    )
    assert result["mde_only"] == [GUID]


def test_entra_unmanaged() -> None:
    result = reconcile(
        _entra(
            {
                "deviceId": GUID,
                "accountEnabled": True,
                "approximateLastSignInDateTime": RECENT,
            }
        ),
        _intune(),
        _mde(),
        now=NOW,
    )
    assert result["entra_unmanaged"] == [GUID]
    assert result["intune_coverage_of_entra"] == 0.0


def test_truncation_propagates() -> None:
    entra = _entra()
    entra["truncated"] = True
    result = reconcile(entra, _intune(), _mde(), now=NOW)
    assert result["truncated"] is True


def test_non_onboarded_mde_excluded() -> None:
    result = reconcile(
        _entra(),
        _intune({"azureADDeviceId": GUID, "lastSyncDateTime": RECENT}),
        _mde({"aadDeviceId": GUID, "onboardingStatus": "CanBeOnboarded", "lastSeen": RECENT}),
        now=NOW,
    )
    assert result["mde_active"] == 0


def _mde_check() -> CheckDefinition:
    return CheckDefinition(id="mde-onboard-gap", title="mde", workload=Workload.DEFENDER)


def test_mde_reconciliation_sets_denominator_source() -> None:
    result = evaluate_mde_onboard_gap(
        _mde_check(),
        {
            "mde_summary": {"onboarded_machines": 95, "truncated": False},
            "device_reconciliation": {"intune_active": 100, "truncated": False},
        },
    )
    assert result.status is FindingStatus.OK
    assert result.evidence["denominator_source"] == "intune_managed_active_30d"
    assert result.confidence is Confidence.HIGH


def test_mde_reconciliation_truncated_is_medium() -> None:
    result = evaluate_mde_onboard_gap(
        _mde_check(),
        {
            "mde_summary": {"onboarded_machines": 95, "truncated": False},
            "device_reconciliation": {"intune_active": 100, "truncated": True},
        },
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.confidence is Confidence.MEDIUM


def test_mde_missing_reconciliation_stays_leverage() -> None:
    result = evaluate_mde_onboard_gap(
        _mde_check(),
        {"mde_summary": {"onboarded_machines": 40, "licensed_units": 100, "truncated": False}},
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.evidence.get("proxy") is True
    assert "denominator_source" not in result.evidence


def test_enrollment_reconciliation_sets_entra_denominator() -> None:
    result = evaluate_endpoint_enrollment_coverage(
        CheckDefinition(
            id="endpoint-enrollment-coverage",
            title="enroll",
            workload=Workload.ENDPOINT,
        ),
        {
            "intune_bundle": {
                "managed_devices": [{"id": "d1"}],
                "truncated": False,
            },
            "device_reconciliation": {"entra_active": 1, "truncated": False},
        },
    )
    assert result.status is FindingStatus.OK
    assert result.evidence["denominator_source"] == "entra_devices_active_30d"
