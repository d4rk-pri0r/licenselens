"""Doctor full-profile ARM probes: onboarding state + DfC pricings, optional rows."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from licenselens.auth import AuthContext, AuthMode
from licenselens.doctor import DoctorCheck, run_doctor
from tests.fake_clients import FakeArmClient, FakeGraphClient, PathHandler, error, ok

CLIENT_ID = "client-app-1"
_SUB = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_WS = (
    f"subscriptions/{_SUB}/resourceGroups/rg-1/providers/"
    "Microsoft.OperationalInsights/workspaces/lab-sentinel-ws"
)
_ONBOARDING = f"{_WS}/providers/Microsoft.SecurityInsights/onboardingStates/default"
_PRICINGS = f"subscriptions/{_SUB}/providers/Microsoft.Security/pricings"


class _FakeToken:
    token = "fake-token"


def _auth() -> AuthContext:
    cred = MagicMock()
    cred.get_token.return_value = _FakeToken()
    return AuthContext(
        mode=AuthMode.CLIENT_SECRET, tenant_id="t1", client_id=CLIENT_ID, credential=cred
    )


def _graph() -> FakeGraphClient:
    fake = FakeGraphClient()
    fake.register_list("/organization", ok({"value": [{"id": "t1", "displayName": "Contoso"}]}))
    fake.register_list("/subscribedSkus", ok({"value": []}))
    fake.register_list("/identity/conditionalAccess/policies", ok({"value": []}))
    fake.register_list("/roleManagement/directory/roleAssignments", ok({"value": []}))
    fake.register_get("/security/secureScores", ok({"value": [{"id": "s1", "controlScores": []}]}))
    return fake


def _arm(
    *,
    onboarding: PathHandler | None = None,
    workspace: PathHandler | None = None,
    pricings: PathHandler | None = None,
) -> FakeArmClient:
    arm = FakeArmClient()
    arm.register_get(_ONBOARDING, onboarding or error(404))
    arm.register_get(_WS, workspace or error(404))
    arm.register_get(_PRICINGS, pricings or error(404))
    return arm


def _check(report, name: str) -> DoctorCheck:
    matches = [c for c in report.checks if c.name == name]
    assert len(matches) == 1, f"expected exactly one {name!r} check, got {len(matches)}"
    return matches[0]


def _run(
    monkeypatch: pytest.MonkeyPatch,
    arm: FakeArmClient,
    *,
    workspace_resource_id: str | None = f"/{_WS}",
    subscription_id: str | None = None,
    profile: str = "full",
):
    monkeypatch.setattr("licenselens.doctor.GraphClient", lambda auth: _graph())
    monkeypatch.setattr("licenselens.collectors.arm.ArmClient", lambda _auth, **_kw: arm)
    monkeypatch.setattr(
        "licenselens.collectors.mde.collect_mde_machine_summary",
        lambda _auth: {"onboarded_machines": 1, "count_method": "test"},
    )
    monkeypatch.setattr(
        "licenselens.collectors.sentinel.collect_sentinel_bundle",
        lambda _auth, _wid: {
            "sentinel_rules": {"total_rules": 0},
            "sentinel_ueba": {},
            "workspace_resource_id": _wid,
        },
    )
    return run_doctor(
        _auth(),
        workspace_resource_id=workspace_resource_id,
        subscription_id=subscription_id,
        profile=profile,
    )


def test_arm_403_rows_are_optional_and_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    report = _run(
        monkeypatch,
        _arm(onboarding=error(403), workspace=error(403), pricings=error(403)),
    )
    onboarding = _check(report, "sentinelOnboardingState")
    assert onboarding.ok is False
    assert onboarding.optional is True
    assert "Microsoft Sentinel Reader" in onboarding.fix
    pricings = _check(report, "defenderForCloudPricings")
    assert pricings.ok is False
    assert pricings.optional is True
    assert "Security Reader" in pricings.fix
    assert report.ready is True


def test_arm_200_rows_ok_without_leaking_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    pricings_ok = ok(
        {
            "value": [
                {"name": "CloudPosture", "properties": {"pricingTier": "Standard"}},
                {"name": "VirtualMachines", "properties": {"pricingTier": "Free"}},
            ]
        }
    )
    report = _run(
        monkeypatch,
        _arm(
            onboarding=ok({"properties": {}}),
            workspace=ok({"properties": {}}),
            pricings=pricings_ok,
        ),
    )
    onboarding = _check(report, "sentinelOnboardingState")
    assert onboarding.ok is True
    pricings = _check(report, "defenderForCloudPricings")
    assert pricings.ok is True
    assert "CloudPosture" in pricings.detail
    assert _SUB not in pricings.detail and _SUB not in onboarding.detail


def test_no_scope_rows_skip_optional(monkeypatch: pytest.MonkeyPatch) -> None:
    report = _run(monkeypatch, _arm(), workspace_resource_id=None, subscription_id=None)
    for name in ("sentinelOnboardingState", "defenderForCloudPricings"):
        row = _check(report, name)
        assert row.ok is True
        assert row.optional is True
        assert "Skipped" in row.detail
    assert report.ready is True


def test_subscription_only_probes_pricings(monkeypatch: pytest.MonkeyPatch) -> None:
    report = _run(
        monkeypatch,
        _arm(pricings=error(403)),
        workspace_resource_id=None,
        subscription_id=_SUB,
    )
    onboarding = _check(report, "sentinelOnboardingState")
    assert onboarding.ok is True and "Skipped" in onboarding.detail
    pricings = _check(report, "defenderForCloudPricings")
    assert pricings.ok is False and pricings.optional is True
    assert "Security Reader" in pricings.fix
    assert report.ready is True


def test_basic_profile_has_no_arm_probe_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    report = _run(monkeypatch, _arm(), profile="basic")
    names = {c.name for c in report.checks}
    assert "sentinelOnboardingState" not in names
    assert "defenderForCloudPricings" not in names
