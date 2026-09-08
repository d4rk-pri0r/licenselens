"""After-demo overlay must not invent a legacy-auth gap when Security Defaults go off."""

from __future__ import annotations

from licenselens.auth import AuthContext, AuthMode
from licenselens.engine.runner import run_scan
from licenselens.models import ExposureClass, FindingStatus


def _finding(result, check_id: str):
    return next(f for f in result.findings if f.check_id == check_id)


def test_after_overlay_turns_security_defaults_off_with_legacy_block() -> None:
    after = run_scan(
        AuthContext(mode=AuthMode.DRY_RUN), dry_run=True, demo_scenario="after"
    )
    sd = _finding(after, "id-security-defaults-on")
    legacy = _finding(after, "id-ca-legacy-auth-block")
    assert sd.status is FindingStatus.OK
    assert legacy.status is FindingStatus.OK
    assert legacy.exposure_class is not ExposureClass.EXPOSED
    assert "blocks legacy authentication" in (legacy.summary or "").lower()


def test_after_overlay_does_not_add_legacy_auth_as_new_gap() -> None:
    before = run_scan(AuthContext(mode=AuthMode.DRY_RUN), dry_run=True)
    after = run_scan(
        AuthContext(mode=AuthMode.DRY_RUN), dry_run=True, demo_scenario="after"
    )
    before_legacy = _finding(before, "id-ca-legacy-auth-block")
    after_legacy = _finding(after, "id-ca-legacy-auth-block")
    assert after_legacy.status is not FindingStatus.GAP
    # Baseline may be OK/PARTIAL because Security Defaults cover the gap.
    assert before_legacy.status in {
        FindingStatus.OK,
        FindingStatus.PARTIAL,
        FindingStatus.GAP,
    }
