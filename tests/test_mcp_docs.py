"""Phase 1 MCP: docs surface (README snippet placement, mcp guide, skill file)."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_readme_has_mcp_snippet_below_install_path():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    install = text.index("pipx install licenselens")
    snippet = text.index("licenselens[mcp]")  # raises if absent
    assert install < snippet, "mcp.json snippet must appear below the install path"
    assert "docs/mcp.md" in text


def test_docs_mcp_page_exists_and_documents_hosts():
    page = ROOT / "docs" / "mcp.md"
    assert page.is_file()
    text = page.read_text(encoding="utf-8")
    assert "posture.assess" in text
    for host in ("Claude", "Cursor"):
        assert host in text
    assert "read-only" in text.lower()


def test_skill_file_exists_and_pins_contract():
    skill = ROOT / "skills" / "licenselens" / "SKILL.md"
    assert skill.is_file()
    text = skill.read_text(encoding="utf-8")
    assert text.startswith("---")  # YAML frontmatter
    assert "name: licenselens" in text
    assert "posture.assess" in text
    assert "not_licensed" in text  # license-constraint rule
    assert "moves" in text and "recommended_next_steps" in text
