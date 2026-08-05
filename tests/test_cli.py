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
