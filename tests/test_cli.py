from pathlib import Path

import yaml
from typer.testing import CliRunner

from licenselens.cli import app

runner = CliRunner()

FIXTURES = Path(__file__).parent / "fixtures"


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Security License Lens" in result.stdout


def test_help_renders_new_commands():
    for cmd in ["diff", "batch", "discover-workspace"]:
        result = runner.invoke(app, [cmd, "--help"])
        assert result.exit_code == 0, result.output
        assert "Usage" in result.stdout


def test_diff_command_writes_markdown(tmp_path: Path):
    out = tmp_path / "diff.md"
    result = runner.invoke(
        app,
        [
            "diff",
            str(FIXTURES / "scan-baseline.json"),
            str(FIXTURES / "scan-new.json"),
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    text = out.read_text(encoding="utf-8")
    assert "Improved: 1" in text
    assert "New gaps: 1" in text


def test_diff_command_missing_input_exits_2(tmp_path: Path):
    result = runner.invoke(
        app,
        ["diff", str(tmp_path / "nope.json"), str(FIXTURES / "scan-new.json")],
    )
    assert result.exit_code == 2


def test_batch_command_dry_run(tmp_path: Path):
    cfg = tmp_path / "tenants.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "tenants": [
                    {"slug": "alpha", "tenant_id": "t-a"},
                    {"slug": "beta", "tenant_id": "t-b"},
                ]
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = runner.invoke(app, ["batch", str(cfg), "--output-dir", str(out)])
    assert result.exit_code == 0, result.output
    assert "alpha" in result.stdout and "beta" in result.stdout
    index = (out / "index.md").read_text(encoding="utf-8")
    assert "alpha" in index and "beta" in index


def test_batch_command_reports_tenant_error(tmp_path: Path):
    cfg = tmp_path / "tenants.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "tenants": [
                    {"slug": "good", "tenant_id": "t-a"},
                    {"slug": "bad", "auth_mode": "client_secret", "tenant_id": "t-b"},
                ]
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = runner.invoke(app, ["batch", str(cfg), "--output-dir", str(out)])
    assert result.exit_code == 2, result.output
    assert "error" in result.stdout.lower()
    assert (out / "index.md").is_file()


def test_doctor_command_invalid_profile_exits_2():
    result = runner.invoke(app, ["doctor", "--profile", "deep"])
    assert result.exit_code == 2
    assert "profile" in result.stdout.lower()


def test_scan_dry_run_prints_top_card(tmp_path: Path):
    result = runner.invoke(app, ["scan", "--dry-run", "--output-dir", str(tmp_path / "out")])
    # Dry-run has actionable gaps -> exit 1, report written, summary shown.
    assert result.exit_code == 1, result.output
    assert "Security posture" in result.stdout
    assert "Licensed capabilities detected: 25" in result.stdout
    assert "Prioritized now (identity, endpoint): 6" in result.stdout
    assert "Fully working (prioritized): 1" in result.stdout
    assert "Need attention (prioritized): 5" in result.stdout
    assert "Priority actions:" in result.stdout
    assert (tmp_path / "out" / "security-license-lens-report.html").is_file()


def test_scan_dry_run_prints_plain_language_exposure(tmp_path: Path):
    result = runner.invoke(app, ["scan", "--dry-run", "--output-dir", str(tmp_path / "out")])

    assert result.exit_code == 1, result.output
    assert "EXPOSED" not in result.stdout
    assert "id-ca-priv-gaps" not in result.stdout


def test_scan_dry_run_rejects_invalid_pack(tmp_path: Path):
    result = runner.invoke(
        app,
        ["scan", "--dry-run", "--pack", "bogus", "--output-dir", str(tmp_path / "out")],
    )
    assert result.exit_code == 2, result.output
    assert "Invalid pack" in result.stdout
    assert "bogus" in result.stdout


def test_scan_non_tty_defaults_to_dry_run(tmp_path: Path):
    # CliRunner is non-interactive; bare scan without --live stays dry-run.
    result = runner.invoke(app, ["scan", "--output-dir", str(tmp_path / "out")])
    assert result.exit_code == 1, result.output
    assert "dry-run" in result.stdout
    assert (tmp_path / "out" / "security-license-lens-report.html").is_file()


def test_scan_live_non_tty_missing_auth_exits_2(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    result = runner.invoke(
        app,
        ["scan", "--live", "--output-dir", str(tmp_path / "out")],
    )
    assert result.exit_code == 2, result.output
    assert (
        "missing auth" in result.stdout.lower() or "interactive terminal" in result.stdout.lower()
    )


def test_scan_interactive_demo_path(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("licenselens.cli_prompts.is_interactive", lambda: True)
    # Mode: 1 = demo sample data. Remaining prompts should not run for dry-run.
    result = runner.invoke(
        app,
        ["scan", "--output-dir", str(tmp_path / "out")],
        input="1\n",
    )
    assert result.exit_code == 1, result.output
    assert "What do you want to scan?" in result.stdout
    assert (tmp_path / "out" / "security-license-lens-report.html").is_file()


def test_resolve_scan_inputs_non_interactive_uses_flags(monkeypatch, tmp_path: Path):
    from licenselens.auth import AuthMode
    from licenselens.cli_prompts import resolve_scan_inputs

    monkeypatch.setattr("licenselens.cli_prompts.is_interactive", lambda: False)
    result = resolve_scan_inputs(
        live=True,
        auth="client_secret",
        tenant_id="t1",
        client_id="c1",
        client_secret="s1",
        output_dir=tmp_path / "r",
        workspace_resource_id="/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/z",
        open_browser=False,
    )
    assert result.live is True
    assert result.auth_mode == AuthMode.CLIENT_SECRET
    assert result.tenant_id == "t1"
    assert result.client_id == "c1"
    assert result.client_secret == "s1"
    assert result.run_doctor is False
    assert result.workspace_resource_id is not None


def test_resolve_scan_inputs_interactive_live_client_secret(monkeypatch, tmp_path: Path):
    from licenselens.auth import AuthMode
    from licenselens.cli_prompts import resolve_scan_inputs

    monkeypatch.setattr("licenselens.cli_prompts.is_interactive", lambda: True)
    prompts = iter(
        [
            "tenant-guid",
            "app-guid",
            "super-secret",
            str(tmp_path / "out"),
        ]
    )
    confirms = iter([False, False, False])  # open, sentinel, doctor
    monkeypatch.setattr("typer.prompt", lambda *a, **k: next(prompts))
    monkeypatch.setattr("typer.confirm", lambda *a, **k: next(confirms))

    result = resolve_scan_inputs(
        live=True,
        auth="client_secret",
        tenant_id=None,
        client_id=None,
        client_secret=None,
        output_dir=Path("reports"),
        workspace_resource_id=None,
        open_browser=False,
    )
    assert result.live is True
    assert result.auth_mode == AuthMode.CLIENT_SECRET
    assert result.tenant_id == "tenant-guid"
    assert result.client_id == "app-guid"
    assert result.client_secret == "super-secret"
    assert result.output_dir == tmp_path / "out"
    assert result.open_browser is False
    assert result.run_doctor is False


def test_demo_command_prints_html_path(tmp_path: Path):
    result = runner.invoke(app, ["demo", "--output-dir", str(tmp_path / "out")])
    assert result.exit_code == 0, result.output
    assert "offline demo scan" in result.stdout
    assert "Licensed capabilities detected: 25" in result.stdout
    assert "security-license-lens-report.html" in result.stdout.replace("\n", "")
    assert (tmp_path / "out" / "security-license-lens-report.html").is_file()


def test_quickstart_help_and_invalid_secret_rail():
    result = runner.invoke(app, ["quickstart", "--help"])
    assert result.exit_code == 0, result.output
    assert "read-only" in result.stdout.lower()

    # Client-secret path without the other credentials -> plain-English rail.
    result = runner.invoke(app, ["quickstart", "--client-secret", "s3cret"])
    assert result.exit_code == 2
    assert "app-only" in result.stdout.lower()
    assert "client_secret" in result.stdout


def test_scan_help_exposes_profile_config_rules_backend_archive():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0, result.output
    help_text = result.stdout
    assert "--profile" in help_text
    assert "--config" in help_text
    assert "--rules" in help_text
    assert "--backend" in help_text
    assert "--report-archive" in help_text


def test_scan_dry_run_with_identity_profile_narrows_scope(tmp_path: Path):
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        ["scan", "--dry-run", "--profile", "identity", "--output-dir", str(out)],
    )
    assert result.exit_code == 1, result.output
    assert "Profile: identity" in result.stdout
    json_path = out / "security-license-lens-report.json"
    assert json_path.is_file()
    payload = yaml.safe_load(json_path.read_text(encoding="utf-8"))
    assert payload["profile_ids"] == ["identity"]
    assert payload["packs_scanned"] == ["identity"]
    check_ids = {finding["check_id"] for finding in payload["findings"]}
    assert "id-ca-priv-gaps" in check_ids
    assert "mde-onboard-gap" not in check_ids
    assert any(cid.startswith("custom:identity:") for cid in check_ids)


def test_scan_omitting_profile_matches_legacy_scope(tmp_path: Path):
    out = tmp_path / "out"
    result = runner.invoke(app, ["scan", "--dry-run", "--output-dir", str(out)])
    assert result.exit_code == 1, result.output
    payload = yaml.safe_load(
        (out / "security-license-lens-report.json").read_text(encoding="utf-8")
    )
    assert payload["profile_ids"] == []
    assert "Prioritized now (identity, endpoint): 6" in result.stdout


def test_scan_invalid_profile_exits_2_before_auth(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    auth_calls: list[object] = []

    def _boom(*_args, **_kwargs):
        auth_calls.append(1)
        raise AssertionError("build_auth_context must not run for bad profile")

    monkeypatch.setattr("licenselens.cli.build_auth_context", _boom)
    result = runner.invoke(
        app,
        [
            "scan",
            "--live",
            "--profile",
            "not-a-real-profile",
            "--auth",
            "client_secret",
            "--tenant-id",
            "t",
            "--client-id",
            "c",
            "--client-secret",
            "s",
            "--output-dir",
            str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 2, result.output
    assert "unknown profile" in result.stdout.lower()
    assert auth_calls == []


def test_scan_invalid_rules_exits_2_before_auth(tmp_path: Path, monkeypatch):
    rules = tmp_path / "bad-rules.yaml"
    rules.write_text("custom_rules: not-a-list\n", encoding="utf-8")
    auth_calls: list[object] = []
    monkeypatch.setattr(
        "licenselens.cli.build_auth_context",
        lambda *a, **k: auth_calls.append(1),
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "--dry-run",
            "--rules",
            str(rules),
            "--output-dir",
            str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 2, result.output
    assert "configuration error" in result.stdout.lower()
    assert auth_calls == []


def test_scan_invalid_backend_exits_2(tmp_path: Path):
    result = runner.invoke(
        app,
        [
            "scan",
            "--dry-run",
            "--backend",
            "telepathy",
            "--output-dir",
            str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 2, result.output
    assert "unknown backend" in result.stdout.lower()


def test_scan_report_archive_writes_zip(tmp_path: Path):
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "scan",
            "--dry-run",
            "--profile",
            "identity",
            "--report-archive",
            "--output-dir",
            str(out),
        ],
    )
    assert result.exit_code == 1, result.output
    assert (out / "security-license-lens-report.zip").is_file()
    assert "ZIP" in result.stdout


def test_demo_profile_and_archive(tmp_path: Path):
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        ["demo", "--profile", "email", "--report-archive", "--output-dir", str(out)],
    )
    assert result.exit_code == 0, result.output
    payload = yaml.safe_load(
        (out / "security-license-lens-report.json").read_text(encoding="utf-8")
    )
    assert payload["profile_ids"] == ["email"]
    assert (out / "security-license-lens-report.zip").is_file()


def test_batch_profile_flag_and_tenant_profile(tmp_path: Path):
    cfg = tmp_path / "tenants.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "defaults": {"profile": "identity"},
                "tenants": [
                    {"slug": "alpha", "tenant_id": "t-a"},
                    {"slug": "beta", "tenant_id": "t-b", "profile": "email"},
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = runner.invoke(app, ["batch", str(cfg), "--output-dir", str(out)])
    assert result.exit_code == 0, result.output
    by_slug = {
        path.relative_to(out).parts[0]: path
        for path in out.rglob("security-license-lens-report.json")
    }
    alpha = yaml.safe_load(by_slug["alpha"].read_text(encoding="utf-8"))
    beta = yaml.safe_load(by_slug["beta"].read_text(encoding="utf-8"))
    assert alpha["profile_ids"] == ["identity"]
    assert beta["profile_ids"] == ["email"]


def test_batch_invalid_cli_profile_exits_2_before_tenants(tmp_path: Path):
    cfg = tmp_path / "tenants.yaml"
    cfg.write_text(
        yaml.safe_dump({"tenants": [{"slug": "alpha", "tenant_id": "t-a"}]}),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        ["batch", str(cfg), "--profile", "nope", "--output-dir", str(tmp_path / "out")],
    )
    assert result.exit_code == 2, result.output
    assert "unknown profile" in result.stdout.lower()
    assert not (tmp_path / "out" / "index.md").exists()


def test_doctor_assessment_profile_prints_requirements():
    result = runner.invoke(app, ["doctor", "--assessment-profile", "identity"])
    assert result.exit_code == 0, result.output
    assert "Assessment profile requirements" in result.stdout
    assert "identity" in result.stdout.lower()
    assert "Capabilities:" in result.stdout
    assert "Permissions:" in result.stdout
    assert "Modules:" in result.stdout


def test_doctor_invalid_assessment_profile_exits_2_before_auth(monkeypatch):
    auth_calls: list[object] = []
    monkeypatch.setattr(
        "licenselens.cli.build_auth_context",
        lambda *a, **k: auth_calls.append(1),
    )
    result = runner.invoke(app, ["doctor", "--assessment-profile", "missing-profile"])
    assert result.exit_code == 2, result.output
    assert "unknown profile" in result.stdout.lower()
    assert auth_calls == []


def test_doctor_probe_profile_still_basic_full_only():
    result = runner.invoke(app, ["doctor", "--profile", "deep"])
    assert result.exit_code == 2
    assert "profile" in result.stdout.lower()


def test_checks_lists_profile_backend_mode_state():
    result = runner.invoke(app, ["checks"])
    assert result.exit_code == 0, result.output
    assert "Profiles" in result.stdout
    assert "Backend" in result.stdout
    assert "Mode" in result.stdout
    assert "State" in result.stdout
    assert "id-ca-pri…" in result.stdout
    assert "identity" in result.stdout
    assert "enabled" in result.stdout
    assert "direct" in result.stdout


def test_quickstart_invalid_profile_exits_2_before_auth(monkeypatch):
    auth_calls: list[object] = []
    monkeypatch.setattr(
        "licenselens.cli.build_auth_context",
        lambda *a, **k: auth_calls.append(1),
    )
    result = runner.invoke(app, ["quickstart", "--profile", "nope"])
    assert result.exit_code == 2, result.output
    assert "unknown profile" in result.stdout.lower()
    assert auth_calls == []


def test_scan_config_overlay_merges_custom_rules(tmp_path: Path):
    config = tmp_path / "org.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0",
                "id": "org-identity",
                "name": "Org identity",
                "custom_rules": [
                    {
                        "id": "org-gap-count",
                        "title": "Org gap count",
                        "selector": "finding.status",
                        "operator": "gte",
                        "value": 1,
                        "collection": "count",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "scan",
            "--dry-run",
            "--profile",
            "identity",
            "--config",
            str(config),
            "--output-dir",
            str(out),
        ],
    )
    assert result.exit_code == 1, result.output
    payload = yaml.safe_load(
        (out / "security-license-lens-report.json").read_text(encoding="utf-8")
    )
    assert payload["profile_ids"] == ["identity", "org-identity"]
    check_ids = {finding["check_id"] for finding in payload["findings"]}
    assert any("org-gap-count" in cid for cid in check_ids)
