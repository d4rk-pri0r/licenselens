"""K11: docs↔CLI drift lock — ``docs/cli.md`` must document every command.

Parses the command registry out of ``src/licenselens/cli.py`` with AST-only
static analysis (no typer import side effects) and cross-checks it against the
``### `command``` sections of ``docs/cli.md`` in both directions, so a command
added or removed without a doc update fails CI.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI_PATH = ROOT / "src" / "licenselens" / "cli.py"
DOCS_PATH = ROOT / "docs" / "cli.md"

COMMAND_HEADING: re.Pattern[str] = re.compile(r"^### `([a-z][a-z0-9-]*)`$", re.MULTILINE)


def _registered_commands() -> dict[str, tuple[str, ...]]:
    """Return command name → (function name, alias names) from the cli.py AST.

    Aliases are additional ``@app.command("...")`` decorators stacked on the
    same function (e.g. ``setup``/``init``).
    """
    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    names_by_function: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr == "command"
                and decorator.args
                and isinstance(decorator.args[0], ast.Constant)
                and isinstance(decorator.args[0].value, str)
            ):
                continue
            names_by_function.setdefault(node.name, []).append(decorator.args[0].value)
    commands: dict[str, tuple[str, ...]] = {}
    for function_name, names in names_by_function.items():
        primary, *aliases = names
        commands[primary] = (function_name, *aliases)
    return commands


def _documented_commands() -> list[str]:
    text = DOCS_PATH.read_text(encoding="utf-8")
    return COMMAND_HEADING.findall(text)


def test_cli_registry_has_the_expected_command_surface():
    commands = _registered_commands()
    assert len(commands) >= 9, f"command registry scan looks broken: {commands}"
    assert "scan" in commands
    assert "demo" in commands
    assert "doctor" in commands


def test_docs_document_every_cli_command():
    documented = set(_documented_commands())
    missing = sorted(set(_registered_commands()) - documented)
    assert not missing, f"docs/cli.md has no section for commands: {missing}"


def test_docs_mention_no_commands_missing_from_cli():
    extra = sorted(set(_documented_commands()) - set(_registered_commands()))
    assert not extra, f"docs/cli.md documents commands not registered in cli.py: {extra}"


def test_command_aliases_are_mentioned_in_docs():
    text = DOCS_PATH.read_text(encoding="utf-8")
    undocumented_aliases = [
        (primary, alias)
        for primary, (_, *aliases) in _registered_commands().items()
        for alias in aliases
        if f"`{alias}`" not in text
    ]
    assert not undocumented_aliases, f"aliases not mentioned in docs/cli.md: {undocumented_aliases}"


def test_documented_command_sections_are_nonempty():
    text = DOCS_PATH.read_text(encoding="utf-8")
    sections = re.split(r"^## ", text, flags=re.MULTILINE)
    command_section = next((section for section in sections if section.startswith("Commands")), "")
    for heading in COMMAND_HEADING.findall(command_section):
        pattern = re.compile(
            rf"^### `{re.escape(heading)}`\n\n(.*?)(?=^### `|\Z)",
            re.MULTILINE | re.DOTALL,
        )
        match = pattern.search(command_section)
        assert match is not None, f"heading parse failure for {heading}"
        body = match.group(1).strip()
        assert body, f"docs/cli.md section for `{heading}` is empty"
