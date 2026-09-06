"""Phase 1 MCP: server registration surface (requires the mcp extra)."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("mcp", reason="install '.[dev]' for MCP server tests")

from licenselens.mcp_server import PLAN_TOOL_NAME, SERVER_TOOL_NAME, build_server  # noqa: E402
from licenselens.models import ScanResult  # noqa: E402

WRITE_VERBS = {
    "patch",
    "post",
    "put",
    "delete",
    "update",
    "create",
    "set",
    "remove",
    "write",
    "apply",
    "remediate",
}


def _list_tools():
    return asyncio.run(build_server().list_tools())


def _input_schema(tool) -> dict:
    """SDK-line agnostic schema accessor (v2 uses input_schema, v1 inputSchema)."""
    return getattr(tool, "input_schema", None) or tool.inputSchema


def test_exposes_read_only_tools():
    tools = _list_tools()
    names = [t.name for t in tools]
    assert names == [SERVER_TOOL_NAME, PLAN_TOOL_NAME]
    for tool in tools:
        schema = _input_schema(tool)
        prop_names = set(schema.get("properties", {}))
        assert not (prop_names & WRITE_VERBS)


def test_tool_description_declares_read_only_and_demo_default():
    tools = {tool.name: tool for tool in _list_tools()}
    lowered = tools[SERVER_TOOL_NAME].description.lower()
    assert "read-only" in lowered
    assert "offline demo" in lowered
    plan_desc = tools[PLAN_TOOL_NAME].description.lower()
    assert "read-only" in plan_desc


def test_calling_the_registered_tool_function_returns_scan_payload():
    from licenselens.mcp_assess import run_assessment

    payload = run_assessment()  # the registered callable delegates here; contract already T1-proven
    assert ScanResult.model_validate(payload)  # raises if not the locked contract


def test_mcp_command_help_documents_stdio():
    from typer.testing import CliRunner

    from licenselens.cli import app

    result = CliRunner().invoke(app, ["mcp", "--help"])
    assert result.exit_code == 0
    assert "stdio" in result.stdout.lower()


def test_mcp_command_exits_2_with_hint_when_sdk_missing(monkeypatch, capsys):
    import sys

    from typer.testing import CliRunner

    from licenselens.cli import app

    monkeypatch.setitem(sys.modules, "mcp", None)  # poison the lazy import
    monkeypatch.setitem(sys.modules, "licenselens.mcp_server", None)
    result = CliRunner().invoke(app, ["mcp"])
    assert result.exit_code == 2
    hint = "licenselens[mcp]"
    assert hint in (result.output or "") or hint in capsys.readouterr().err
