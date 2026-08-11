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
    assert "Your security at a glance" in result.stdout
    assert "Licensed capabilities detected: 8" in result.stdout
    assert "Prioritized now (identity, endpoint): 4" in result.stdout
    assert "Fully working (prioritized): 1" in result.stdout
    assert "Need attention (prioritized): 3" in result.stdout
    assert "Top things to do first:" in result.stdout
    assert (tmp_path / "out" / "security-license-lens-report.html").is_file()


def test_scan_dry_run_prints_plain_language_exposure(tmp_path: Path):
    result = runner.invoke(app, ["scan", "--dry-run", "--output-dir", str(tmp_path / "out")])

    assert result.exit_code == 1, result.output
    assert "EXPOSED (1):" in result.stdout
    assert "Powerful accounts may sign in without strong extra checks" in result.stdout
    assert "id-ca-priv-gaps" not in result.stdout


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
    assert "Licensed capabilities detected: 8" in result.stdout
    assert "security-license-lens-report.html" in result.stdout
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
