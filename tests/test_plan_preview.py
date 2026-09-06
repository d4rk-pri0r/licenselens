"""WS5-B: execution-plan preview."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from licenselens.auth import REQUIRED_GRAPH_APP_PERMISSIONS
from licenselens.engine.plan_preview import (
    build_plan_preview,
    render_plan_json,
    render_plan_markdown,
    skus_from_assume,
)


def test_demo_plan_deterministic_two_runs_equal() -> None:
    first = build_plan_preview()
    second = build_plan_preview()
    assert first.to_dict() == second.to_dict()
    assert render_plan_markdown(first) == render_plan_markdown(second)
    assert render_plan_json(first) == render_plan_json(second)


def test_full_scope_permissions_equal_required_constant() -> None:
    preview = build_plan_preview()
    assert preview.graph_permissions == REQUIRED_GRAPH_APP_PERMISSIONS


def test_assume_sku_resolves_e5_capabilities() -> None:
    skus = skus_from_assume(["SPE_E5"])
    preview = build_plan_preview(skus=skus)
    assert "SPE_E5" in preview.sku_part_numbers
    assert "conditional_access" in preview.owned
    assert preview.will_evaluate


def test_plan_markdown_has_required_sections() -> None:
    text = render_plan_markdown(build_plan_preview())
    assert "## Entitlements resolved" in text
    assert "## Checks" in text
    assert "## Collectors" in text
    assert "## Totals" in text
    assert "## What this tool will never do" in text
    assert "No writes" in text


def test_plan_demo_writes_md(tmp_path: Path) -> None:
    from licenselens.cli import app

    result = CliRunner().invoke(app, ["plan", "--demo", "-o", str(tmp_path), "--format", "md"])
    assert result.exit_code == 0, result.stdout
    path = tmp_path / "plan.md"
    assert path.is_file()
    body = path.read_text(encoding="utf-8")
    assert body.startswith("# Execution plan")
    assert "conditional_access" in body
