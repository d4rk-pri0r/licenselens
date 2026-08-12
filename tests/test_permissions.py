"""Keep REQUIRED_GRAPH_APP_PERMISSIONS in sync with the permission docs."""

from __future__ import annotations

import re
from pathlib import Path

from licenselens.auth import REQUIRED_GRAPH_APP_PERMISSIONS

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = REPO_ROOT / "docs"

# Table rows in the Graph section of permissions.md: | `Permission.Name` | ... |
_TABLE_ROW = re.compile(r"^\| `([A-Za-z.]+)` \|")
# Bullet list entries under "**Microsoft Graph (application)**" in app-registration.md.
_BULLET = re.compile(r"^- `([A-Za-z.]+)`")


def _graph_permissions_from_permissions_md() -> set[str]:
    text = (DOCS_DIR / "permissions.md").read_text(encoding="utf-8")
    in_graph_section = False
    names: set[str] = set()
    for line in text.splitlines():
        if line.startswith("## "):
            in_graph_section = "Microsoft Graph" in line
            continue
        if not in_graph_section:
            continue
        match = _TABLE_ROW.match(line)
        if match:
            names.add(match.group(1))
    return names


def _graph_permissions_from_app_registration_md() -> set[str]:
    text = (DOCS_DIR / "app-registration.md").read_text(encoding="utf-8")
    in_graph_section = False
    names: set[str] = set()
    for line in text.splitlines():
        if line.startswith("**"):
            in_graph_section = "Microsoft Graph" in line and "application" in line.lower()
            continue
        if not in_graph_section:
            continue
        match = _BULLET.match(line)
        if match:
            names.add(match.group(1))
    return names


def test_tuple_has_no_duplicates():
    assert len(REQUIRED_GRAPH_APP_PERMISSIONS) == len(set(REQUIRED_GRAPH_APP_PERMISSIONS))


def test_permissions_md_graph_table_matches_tuple():
    doc_permissions = _graph_permissions_from_permissions_md()
    assert doc_permissions == set(REQUIRED_GRAPH_APP_PERMISSIONS)


def test_app_registration_md_graph_list_matches_tuple():
    doc_permissions = _graph_permissions_from_app_registration_md()
    assert doc_permissions == set(REQUIRED_GRAPH_APP_PERMISSIONS)
