"""CLI tests for ``licenselens ui`` (T13)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from licenselens.cli import app

runner = CliRunner()

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_BOX_DRAWING_RE = re.compile(r"[─│┌┐└┘├┤┬┴┼╭╮╰╯]")


def _clean_help_output(text: str) -> str:
    """Strip ANSI escapes and Rich box-drawing, collapse whitespace.

    Substitutes with empty string, not space: Rich wraps each hyphen of
    ``--demo`` in its own CSI sequence, and replacing those with spaces
    produced ``- -demo`` on CI (GitHub Actions 33326762718 / 33326762728).
    """
    cleaned = _BOX_DRAWING_RE.sub("", _ANSI_RE.sub("", text))
    return " ".join(cleaned.split())


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


def test_ui_help_lists_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    # CI runners can resolve a very narrow Rich console, which truncates
    # option tokens (e.g. "--d…") mid-name. Pin a wide console so flag
    # names render contiguously, and assert against a cleaned capture.
    monkeypatch.setenv("COLUMNS", "100")
    result = runner.invoke(app, ["ui", "--help"])
    assert result.exit_code == 0
    output = _clean_help_output(result.output)
    compact = output.replace(" ", "")
    assert "--demo" in compact
    assert "--host" in compact
    assert "--port" in compact
