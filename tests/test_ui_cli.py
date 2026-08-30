"""CLI tests for ``licenselens ui`` (T13)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from licenselens.cli import app

runner = CliRunner()


def test_ui_without_demo_exits_2_in_non_tty() -> None:
    result = runner.invoke(app, ["ui"])
    assert result.exit_code == 2
    assert "interactive terminal" in result.output


def test_ui_demo_writes_report(tmp_path: Path) -> None:
    result = runner.invoke(app, ["ui", "--demo", "-o", str(tmp_path)])
    assert result.exit_code == 0
    html_files = list(tmp_path.rglob("security-license-lens-report.html"))
    assert html_files, result.output


def test_ui_rejects_non_loopback_host() -> None:
    result = runner.invoke(app, ["ui", "--host", "0.0.0.0"])
    assert result.exit_code == 2
    result = runner.invoke(app, ["ui", "--host", "example.com"])
    assert result.exit_code == 2


def test_ui_help_lists_flags() -> None:
    result = runner.invoke(app, ["ui", "--help"])
    assert result.exit_code == 0
    assert "--demo" in result.output
    assert "--host" in result.output
    assert "--port" in result.output
