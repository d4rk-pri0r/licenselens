from licenselens.auth import AuthMode, build_auth_context
from licenselens.doctor import run_doctor


def test_doctor_dry_run_ok():
    ctx = build_auth_context(mode=AuthMode.DRY_RUN)
    report = run_doctor(ctx)
    assert report.ok
    assert report.checks[0].name == "mode"
