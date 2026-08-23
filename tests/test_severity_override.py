"""Config-driven severity overrides, omissions, and annotations.

Covers the G4 seam: a profile may declare ``severity_override`` entries that
flip ``Finding.severity`` for matching ``check_id`` values, plus free-text
``omissions`` and owner/reason ``annotations`` that surface in the report
provenance. The pydantic ``AssessmentProfile`` model is the single source of
truth (``extra="forbid"``), so unknown override check ids and duplicate
override check ids fail closed at config load, before any auth.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from typer.testing import CliRunner

from licenselens.auth import AuthMode, build_auth_context
from licenselens.cli import app
from licenselens.config_models import AssessmentProfile
from licenselens.engine.loader import load_checks
from licenselens.engine.profiles import (
    ProfileReferenceError,
    apply_profile_to_scan_result,
    compose_profile,
    resolve_profile_checks,
)
from licenselens.engine.runner import run_scan
from licenselens.report.viewmodel import build_provenance

runner = CliRunner()


def _profile(raw: dict[str, object]) -> AssessmentProfile:
    return AssessmentProfile.model_validate({"schema_version": "1.0", "name": "Org"} | raw)


def test_severity_override_flips_finding_severity_in_json_output() -> None:
    # Given: a gap finding whose baseline severity is high.
    auth = build_auth_context(mode=AuthMode.DRY_RUN, tenant_id="dry-run")
    base = run_scan(auth, dry_run=True)
    target = next(f for f in base.findings if f.check_id == "id-ca-legacy-auth-block")
    assert target.severity.value == "high"

    # When: a profile overrides that check to critical and the scan runs with it.
    org = _profile(
        {
            "id": "org-override",
            "severity_override": [{"check_id": target.check_id, "severity": "critical"}],
        }
    )
    result = run_scan(auth, dry_run=True, profile=compose_profile("core", organization_profile=org))

    # Then: the finding severity flips to critical in the JSON output.
    flipped = next(f for f in result.findings if f.check_id == target.check_id)
    assert flipped.severity.value == "critical"
    dumped = result.model_dump(mode="json")
    flipped_json = next(f for f in dumped["findings"] if f["check_id"] == target.check_id)
    assert flipped_json["severity"] == "critical"


def test_severity_override_flips_finding_severity_in_html_output(tmp_path: Path) -> None:
    from licenselens.report.html import write_html_report

    auth = build_auth_context(mode=AuthMode.DRY_RUN, tenant_id="dry-run")
    base = run_scan(auth, dry_run=True)
    target = next(f for f in base.findings if f.check_id == "id-ca-legacy-auth-block")
    assert target.severity.value == "high"

    org = _profile(
        {
            "id": "org-override-html",
            "severity_override": [{"check_id": target.check_id, "severity": "critical"}],
        }
    )
    result = run_scan(auth, dry_run=True, profile=compose_profile("core", organization_profile=org))

    html = write_html_report(result, tmp_path / "report.html").read_text(encoding="utf-8")
    row = next(line for line in html.splitlines() if f'data-check-id="{target.check_id}"' in line)
    assert 'data-severity="critical"' in row


def test_existing_waiver_and_exclusion_profiles_still_validate() -> None:
    # Given: a profile carrying the pre-existing accepted-risk and exclusion fields.
    raw = {
        "schema_version": "1.0",
        "id": "legacy-profile",
        "name": "Legacy",
        "packs": ["identity"],
        "accepted_risks": [
            {
                "id": "risk-ca",
                "check_id": "id-ca-priv-gaps",
                "owner": "security@example.com",
                "reason": "Migration accepted.",
                "expires_on": "2099-12-31",
            }
        ],
        "exclusions": [
            {
                "id": "exclude-lab",
                "check_id": "id-ca-priv-gaps",
                "owner": "sec",
                "reason": "Lab tenant.",
            }
        ],
    }

    # When / Then: the profile still validates unchanged (no regression).
    profile = AssessmentProfile.model_validate(raw)
    assert profile.accepted_risks[0].id == "risk-ca"
    assert profile.exclusions[0].id == "exclude-lab"
    assert profile.severity_override == []


def test_unknown_override_check_id_exits_2_at_config_load_before_auth(tmp_path: Path) -> None:
    # Given: a config file whose severity_override names a check that does not exist.
    config = tmp_path / "bad-override.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0",
                "id": "bad-override",
                "name": "Bad override",
                "severity_override": [{"check_id": "no-such-check", "severity": "critical"}],
            }
        ),
        encoding="utf-8",
    )

    # When: the scan resolves the profile before any auth.
    result = runner.invoke(
        app,
        ["scan", "--dry-run", "--profile", "core", "--config", str(config)],
    )

    # Then: config load fails with exit code 2 and a typed diagnostic, no token request.
    assert result.exit_code == 2, result.output
    assert "Configuration error" in result.stdout
    assert "unknown check" in result.stdout


def test_duplicate_override_check_id_is_rejected_at_load() -> None:
    # Given: a profile with two severity overrides for the same check.
    raw = {
        "schema_version": "1.0",
        "id": "dup-override",
        "name": "Duplicate override",
        "severity_override": [
            {"check_id": "id-ca-priv-gaps", "severity": "critical"},
            {"check_id": "id-ca-priv-gaps", "severity": "high"},
        ],
    }

    # When / Then: schema parsing rejects the duplicate check_id before composition.
    with pytest.raises(ValidationError) as exc_info:
        AssessmentProfile.model_validate(raw)
    assert "duplicate severity override check_id" in str(exc_info.value)


def test_unknown_override_check_id_fails_resolution() -> None:
    # Given: a profile whose override names an unknown check.
    profile = _profile(
        {
            "id": "bad-override",
            "severity_override": [{"check_id": "no-such-check", "severity": "critical"}],
        }
    )

    # When / Then: check resolution fails closed with a typed error.
    with pytest.raises(ProfileReferenceError) as exc_info:
        resolve_profile_checks(profile, load_checks())
    assert "unknown check" in str(exc_info.value)


def test_omissions_and_annotations_surface_in_report_provenance() -> None:
    # Given: a profile with omissions and owner/reason annotations.
    auth = build_auth_context(mode=AuthMode.DRY_RUN, tenant_id="dry-run")
    base = run_scan(auth, dry_run=True)
    org = _profile(
        {
            "id": "org-notes",
            "omissions": ["Email pack not assessed this cycle."],
            "annotations": [
                {"owner": "security@example.com", "reason": "Reviewed by security team."}
            ],
        }
    )
    resolved = compose_profile("core", organization_profile=org)

    # When: the profile metadata is carried onto the scan result and the report context.
    result = apply_profile_to_scan_result(base, resolved)
    provenance = build_provenance(result)

    # Then: the provenance surfaces the omissions and annotations.
    assert provenance["omissions"] == ["Email pack not assessed this cycle."]
    assert provenance["annotations"] == [
        {"owner": "security@example.com", "reason": "Reviewed by security team."}
    ]
