"""Report redaction contract tests.

Lock the privacy promise of the 1.0 line: a resolved profile's
``redaction`` settings (schema default ``enabled: true``) actually apply at
report-writing time. A hostile scan result carrying a real tenant id, user
principal names, and the tenant's own domain must render ``[redacted]`` — never
the raw value — across all four output surfaces (HTML, JSON, Markdown, and the
bundle's embedded ``DATA_JS``/``VIEWMODEL_JS``), while the ``--no-redact`` path
preserves raw values.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from licenselens.cli import _effective_redaction_settings, app
from licenselens.config_models import RedactionSettings
from licenselens.engine.profiles import compose_profile
from licenselens.models import (
    BlastRadius,
    CheckPack,
    Confidence,
    Effort,
    ExposureClass,
    Finding,
    FindingStatus,
    ScanResult,
    Severity,
    ValueImpact,
    Workload,
)
from licenselens.report.bundle import build_report_bundle
from licenselens.report.html import write_html_report
from licenselens.report.json_report import write_json_report
from licenselens.report.manifest import ENTRY_FILENAME
from licenselens.report.markdown import write_markdown_report
from licenselens.report.redaction import (
    RedactionTargets,
    derive_redaction_targets,
    redact_text,
)

#: Hostile literals — a real-looking tenant id, two UPNs on two tenant domains,
#: and the bare domain strings. Every one must be unrecoverable from a redacted
#: render.
TENANT_ID = "9f8c1a2e-3b4d-4e5f-6a7b-8c9d0e1f2a3b"
UPN_PRIMARY = "breakglass.admin@contoso.onmicrosoft.com"
UPN_DELEGATED = "soc.partner@contoso.com"
DOMAIN_PRIMARY = "contoso.onmicrosoft.com"
DOMAIN_ALT = "contoso.com"

REPLACEMENT = "[redacted]"

runner = CliRunner()

# GITHUB_ACTIONS/FORCE_COLOR make Typer's rich highlighter split "--opt" into
# colored "-" + "-opt", so assert on ANSI-stripped help text (mirrors test_cli).
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def hostile_report() -> ScanResult:
    """A scan result whose tenant id, UPNs, and tenant domains are everywhere."""
    finding = Finding(
        check_id="id-ca-priv-gaps",
        title="Conditional Access MFA is not enforced",
        workload=Workload.IDENTITY,
        status=FindingStatus.GAP,
        severity=Severity.CRITICAL,
        value_impact=ValueImpact.HIGH,
        impact=ValueImpact.HIGH,
        effort=Effort.HOURS,
        blast_radius=BlastRadius.ALL_USERS,
        pack=CheckPack.IDENTITY,
        exposure_class=ExposureClass.EXPOSED,
        confidence=Confidence.MEDIUM,
        summary=(
            f"Tenant {TENANT_ID} has no CA policy. Delegated admin {UPN_DELEGATED} "
            f"and break-glass {UPN_PRIMARY} authenticate against {DOMAIN_PRIMARY}."
        ),
        customer_summary=(f"Sign-in for {UPN_PRIMARY} on domain {DOMAIN_ALT} is not protected."),
        customer_next_step="Turn on MFA before the next scan.",
        remediation="Enable an MFA Conditional Access policy.",
        evidence={
            "tenantId": TENANT_ID,
            "userPrincipalName": UPN_PRIMARY,
            "dormant_sample": [{"userPrincipalName": UPN_DELEGATED}],
            "domain": DOMAIN_PRIMARY,
        },
        data_sources=["microsoft.graph"],
        limitations=["Sample evidence."],
    )
    return ScanResult(
        version="1.0.0-test",
        tenant_id=TENANT_ID,
        tenant_display_name="Contoso Ltd",
        scan_mode="dry_run",
        scanned_at="2026-08-16T09:30:00+00:00",
        findings=[finding],
        workspace_resource_id=(
            f"/subscriptions/{TENANT_ID}/resourceGroups/rg/"
            "providers/Microsoft.OperationalInsights/workspaces/ws"
        ),
        warnings=[f"Mail for {UPN_PRIMARY} bounced at {DOMAIN_PRIMARY}."],
        packs_scanned=["identity"],
        exposed_check_ids=["id-ca-priv-gaps"],
        has_exposed=True,
    )


ALL_ON = RedactionSettings(
    enabled=True,
    redact_tenant_ids=True,
    redact_user_principals=True,
    redact_domains=True,
    replacement=REPLACEMENT,
)

RAW_VALUES = (TENANT_ID, UPN_PRIMARY, UPN_DELEGATED, DOMAIN_PRIMARY, DOMAIN_ALT)


# ---------------------------------------------------------------------------
# The transform itself
# ---------------------------------------------------------------------------


def test_redact_text_strips_all_classes() -> None:
    text = (
        f"tenant={TENANT_ID} upn={UPN_PRIMARY} alt={UPN_DELEGATED} "
        f"domain={DOMAIN_PRIMARY} bare={DOMAIN_ALT}"
    )
    targets = RedactionTargets(
        tenant_ids=(TENANT_ID,),
        domains=(DOMAIN_PRIMARY, DOMAIN_ALT),
    )
    out = redact_text(text, targets=targets, settings=ALL_ON)
    for raw in RAW_VALUES:
        assert raw not in out
    assert out.count(REPLACEMENT) == 5


def test_redact_text_disabled_preserves_raw() -> None:
    text = f"tenant={TENANT_ID} upn={UPN_PRIMARY} domain={DOMAIN_PRIMARY}"
    targets = RedactionTargets(tenant_ids=(TENANT_ID,), domains=(DOMAIN_PRIMARY,))
    out = redact_text(
        text,
        targets=targets,
        settings=ALL_ON.model_copy(update={"enabled": False}),
    )
    assert out == text


def test_redact_text_flags_gate_each_class() -> None:
    text = f"tenant={TENANT_ID} upn={UPN_PRIMARY} domain={DOMAIN_PRIMARY}"
    targets = RedactionTargets(tenant_ids=(TENANT_ID,), domains=(DOMAIN_PRIMARY,))

    # Schema default: domains off → domain survives, tenant id + UPN stripped.
    out = redact_text(text, targets=targets, settings=RedactionSettings())
    assert TENANT_ID not in out
    assert UPN_PRIMARY not in out
    assert DOMAIN_PRIMARY in out

    # tenant ids off → only the UPN is stripped.
    out = redact_text(
        text,
        targets=targets,
        settings=RedactionSettings(redact_tenant_ids=False),
    )
    assert TENANT_ID in out
    assert UPN_PRIMARY not in out


def test_redact_text_custom_replacement() -> None:
    text = f"upn={UPN_PRIMARY}"
    targets = RedactionTargets(tenant_ids=(), domains=())
    out = redact_text(
        text,
        targets=targets,
        settings=RedactionSettings(replacement="<secret>"),
    )
    assert "<secret>" in out
    assert UPN_PRIMARY not in out


def test_redact_text_masked_upn_is_consumed_whole() -> None:
    # The dormant-privileged evaluator emits masked local parts; the domain is
    # still tenant data and must not survive redaction.
    masked = "u***@contoso.onmicrosoft.com"
    targets = RedactionTargets(tenant_ids=(), domains=(DOMAIN_PRIMARY,))
    out = redact_text(
        f"sample={masked}",
        targets=targets,
        settings=RedactionSettings(redact_user_principals=True),
    )
    assert masked not in out
    assert DOMAIN_PRIMARY not in out


def test_derive_targets_harvests_tenant_id_and_upn_domains() -> None:
    targets = derive_redaction_targets(hostile_report())
    assert targets.tenant_ids == (TENANT_ID,)
    assert DOMAIN_ALT in targets.domains
    assert DOMAIN_PRIMARY in targets.domains


# ---------------------------------------------------------------------------
# The four output surfaces
# ---------------------------------------------------------------------------


def test_json_report_redacted(tmp_path: Path) -> None:
    out = write_json_report(hostile_report(), tmp_path / "r.json", redaction=ALL_ON)
    text = out.read_text(encoding="utf-8")
    assert REPLACEMENT in text
    for raw in RAW_VALUES:
        assert raw not in text
    # The JSON must still parse — redaction only swaps string content.
    payload = json.loads(text)
    assert payload["tenant_id"] == REPLACEMENT


def test_markdown_report_redacted(tmp_path: Path) -> None:
    out = write_markdown_report(hostile_report(), tmp_path / "r.md", redaction=ALL_ON)
    text = out.read_text(encoding="utf-8")
    assert REPLACEMENT in text
    for raw in RAW_VALUES:
        assert raw not in text


def test_html_report_redacted(tmp_path: Path) -> None:
    out = write_html_report(hostile_report(), tmp_path / "r.html", redaction=ALL_ON)
    text = out.read_text(encoding="utf-8")
    assert REPLACEMENT in text
    for raw in RAW_VALUES:
        assert raw not in text


def test_bundle_data_js_and_entry_redacted(tmp_path: Path) -> None:
    bundle = build_report_bundle(hostile_report(), tmp_path / "bundle", redaction=ALL_ON)
    data_files = list(bundle.assets_dir.glob("report-data-*.js"))
    assert data_files, "bundle must embed a report-data asset"
    data_text = data_files[0].read_text(encoding="utf-8")
    assert REPLACEMENT in data_text
    for raw in RAW_VALUES:
        assert raw not in data_text

    entry_text = (bundle.root / ENTRY_FILENAME).read_text(encoding="utf-8")
    assert REPLACEMENT in entry_text
    for raw in RAW_VALUES:
        assert raw not in entry_text


def test_unredacted_path_preserves_raw_values(tmp_path: Path) -> None:
    """The ``--no-redact`` contract at the writer seam: raw values survive."""
    result = hostile_report()
    html = write_html_report(
        result, tmp_path / "r.html", redaction=ALL_ON.model_copy(update={"enabled": False})
    ).read_text(encoding="utf-8")
    js = write_json_report(
        result, tmp_path / "r.json", redaction=ALL_ON.model_copy(update={"enabled": False})
    ).read_text(encoding="utf-8")
    md = write_markdown_report(
        result, tmp_path / "r.md", redaction=ALL_ON.model_copy(update={"enabled": False})
    ).read_text(encoding="utf-8")
    bundle = build_report_bundle(
        result,
        tmp_path / "bundle",
        redaction=ALL_ON.model_copy(update={"enabled": False}),
    )
    data_text = next(bundle.assets_dir.glob("report-data-*.js")).read_text(encoding="utf-8")

    for text in (html, js, data_text):
        assert TENANT_ID in text
        assert UPN_PRIMARY in text
    assert REPLACEMENT not in html
    assert REPLACEMENT not in data_text
    # Markdown shows the display name in the org line; the hostile UPN and
    # domain still flow through the finding body when redaction is off.
    assert UPN_PRIMARY in md
    assert DOMAIN_ALT in md


def test_writers_without_redaction_argument_are_unchanged(tmp_path: Path) -> None:
    """Library default: no redaction argument means no transform (compat)."""
    out = write_json_report(hostile_report(), tmp_path / "r.json")
    text = out.read_text(encoding="utf-8")
    assert TENANT_ID in text
    assert UPN_PRIMARY in text
    assert REPLACEMENT not in text


# ---------------------------------------------------------------------------
# CLI flag plumbing
# ---------------------------------------------------------------------------


def test_effective_redaction_defaults_on_without_profile() -> None:
    settings = _effective_redaction_settings(None, None)
    assert settings.enabled is True
    assert settings.redact_tenant_ids is True
    assert settings.redact_user_principals is True
    assert settings.redact_domains is False


def test_effective_redaction_no_redact_flag_opts_out() -> None:
    settings = _effective_redaction_settings(None, False)
    assert settings.enabled is False


def test_effective_redaction_flag_overrides_profile() -> None:
    resolved = compose_profile("core")
    settings = _effective_redaction_settings(resolved, False)
    assert settings.enabled is False
    assert settings.redact_tenant_ids is True  # only the master switch flipped
    settings = _effective_redaction_settings(resolved, True)
    assert settings.enabled is True


def test_effective_redaction_profile_domains_flag_flows_through() -> None:
    resolved = compose_profile("email")
    settings = _effective_redaction_settings(resolved, None)
    assert settings.enabled is True
    assert settings.redact_domains is True


def test_demo_default_redacts_tenant_id(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = runner.invoke(app, ["demo", "--output-dir", str(out)])
    assert result.exit_code == 0, result.output
    payload = json.loads((out / "security-license-lens-report.json").read_text(encoding="utf-8"))
    assert payload["tenant_id"] == REPLACEMENT
    html = (out / "security-license-lens-report.html").read_text(encoding="utf-8")
    assert REPLACEMENT in html
    assert "00000000-0000-0000-0000-000000000000" not in html


def test_demo_no_redact_preserves_raw_tenant_id(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = runner.invoke(app, ["demo", "--no-redact", "--output-dir", str(out)])
    assert result.exit_code == 0, result.output
    payload = json.loads((out / "security-license-lens-report.json").read_text(encoding="utf-8"))
    assert payload["tenant_id"] == "00000000-0000-0000-0000-000000000000"


def test_scan_help_lists_redact_flag() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0, result.output
    help_text = _ANSI_ESCAPE.sub("", result.stdout or result.output)
    assert "--redact" in help_text
    assert "--no-redact" in help_text
