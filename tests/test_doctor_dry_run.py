import pytest

from licenselens.auth import AuthMode, build_auth_context
from licenselens.doctor import DoctorCheck, DoctorProfile, DoctorReport, run_doctor


def test_doctor_dry_run_ok():
    ctx = build_auth_context(mode=AuthMode.DRY_RUN)
    report = run_doctor(ctx)
    assert report.ok
    assert report.checks[0].name == "mode"
    assert report.profile == DoctorProfile.BASIC


def test_doctor_dry_run_full_profile_ok():
    ctx = build_auth_context(mode=AuthMode.DRY_RUN)
    report = run_doctor(ctx, profile="full")
    assert report.ok
    assert report.profile == DoctorProfile.FULL
    assert "--profile full" in report.checks[0].detail


def test_doctor_rejects_unknown_profile():
    ctx = build_auth_context(mode=AuthMode.DRY_RUN)
    with pytest.raises(ValueError):
        run_doctor(ctx, profile="deep")


def test_doctor_accepts_profile_enum():
    ctx = build_auth_context(mode=AuthMode.DRY_RUN)
    report = run_doctor(ctx, profile=DoctorProfile.FULL)
    assert report.profile == DoctorProfile.FULL


def test_doctor_ready_enough_despite_optional_probe_failure():
    report = DoctorReport(
        mode=AuthMode.DEVICE_CODE,
        checks=[
            DoctorCheck(name="credential", ok=True, detail="ok"),
            DoctorCheck(
                name="defenderEndpoint",
                ok=False,
                detail="403",
                optional=True,
                fix="optional",
            ),
        ],
    )
    assert report.ok is False
    assert report.ready is True


def test_doctor_not_ready_when_essential_check_fails():
    report = DoctorReport(
        mode=AuthMode.DEVICE_CODE,
        checks=[
            DoctorCheck(name="credential", ok=True, detail="ok"),
            DoctorCheck(name="conditionalAccess", ok=False, detail="403"),
        ],
    )
    assert report.ready is False
