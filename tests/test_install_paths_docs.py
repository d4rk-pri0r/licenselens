"""Lock the install-path promises in the operator-facing docs (todo 7, P6).

The stage1-product-polish docs rewrite made ``pipx install licenselens`` from
PyPI the sole primary install action on every platform (real today — the wheel
bundles the PowerShell collector bridge since 0.4.0), demoted the standalone
per-user Windows installer (``Install-LicenseLens.ps1`` / ``-ReleaseBaseUrl``)
to a secondary future/release-engineer path with an explicit unavailability
marker, separated operator setup from contributor setup, and refused to invent
release assets that do not exist.

These tests fail CI if any of those promises regress: a dead primary Windows
action reappearing, a contributor step leaking onto an operator surface, an
invented asset (brew / winget / docker pull / a hardcoded windows-x64 zip
literal), an ``irm | iex`` download-and-execute recommendation, or a
repo-relative checkout path on an operator surface.

``docs/reference/*`` is generated and deliberately excluded from the scans.
"""

from __future__ import annotations

import re
from pathlib import Path

from licenselens.windows_installer import no_irm_iex_recommendation

ROOT = Path(__file__).resolve().parents[1]

README = ROOT / "README.md"
DOCS = ROOT / "docs"

# Operator surfaces: pages where an end user decides how to install the tool.
OPERATOR_SURFACES = [
    README,
    DOCS / "index.md",
    DOCS / "package-readme.md",
    DOCS / "getting-started.md",
    DOCS / "windows.md",
]

# Primary surfaces where the standalone installer must never appear.
INSTALLER_FREE_SURFACES = [
    README,
    DOCS / "index.md",
    DOCS / "package-readme.md",
]

# Files that may describe the secondary release-artifact workflow.
SECONDARY_WORKFLOW_FILES = [
    DOCS / "getting-started.md",
    DOCS / "windows.md",
]

INSTALLER_MARKERS = ("Install-LicenseLens.ps1", "-ReleaseBaseUrl")
UNAVAILABILITY_MARKERS = ("not yet available", "signed/promotable")
CONTRIBUTOR_STEPS = ("pip install -e", ".venv", "git clone")
INVENTED_ASSET_TERMS = ("brew", "winget", "docker pull")
REPO_RELATIVE_TERMS = ("./powershell/", "packaging/windows")
WINDOWS_X64_LITERAL = re.compile(r"licenselens-windows-x64-\d")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _lines(path: Path) -> list[str]:
    return _read(path).splitlines()


def _line_index(lines: list[str], needle: str) -> int | None:
    for index, line in enumerate(lines):
        if needle in line:
            return index
    return None


def _scanned_docs() -> list[Path]:
    """README.md + all docs markdown, excluding the generated docs/reference/."""
    return [
        README,
        *(path for path in sorted(DOCS.rglob("*.md")) if "reference" not in path.parts),
    ]


def test_primary_install_actions_present() -> None:
    # pipx is the primary install on every operator surface.
    for path in OPERATOR_SURFACES:
        content = _read(path)
        rel = path.relative_to(ROOT).as_posix()
        assert "pipx install licenselens" in content, f"{rel} is missing the pipx primary install"

    # The demo/quickstart command must be co-located with a pipx install line
    # (the first pipx mention may be prose, so check every occurrence).
    for path in OPERATOR_SURFACES:
        lines = _lines(path)
        rel = path.relative_to(ROOT).as_posix()
        pipx_indexes = [
            index for index, line in enumerate(lines) if "pipx install licenselens" in line
        ]
        assert pipx_indexes, f"{rel} has no pipx install line to co-locate with"
        co_located = False
        for pipx_index in pipx_indexes:
            window = lines[max(0, pipx_index - 6) : pipx_index + 7]
            if any(
                "licenselens demo" in line or "licenselens quickstart" in line for line in window
            ):
                co_located = True
                break
        assert co_located, (
            f"{rel}: pipx install has no co-located `licenselens demo`/`quickstart` line"
        )

    # Sample-report link and Windows guide references.
    assert "sample-report.html" in _read(DOCS / "index.md"), (
        "docs/index.md lost the sample-report link"
    )
    assert "sample-report.html" in _read(DOCS / "getting-started.md"), (
        "docs/getting-started.md lost the sample-report link"
    )
    assert "windows.md" in _read(README), "README.md no longer references windows.md"
    assert "windows.md" in _read(DOCS / "index.md"), "docs/index.md no longer references windows.md"


def test_windows_primary_action_is_pipx() -> None:
    # Primary operator surfaces: installer commands are absent, pipx is present.
    for path in INSTALLER_FREE_SURFACES:
        content = _read(path)
        rel = path.relative_to(ROOT).as_posix()
        assert "pipx install licenselens" in content, f"{rel}: Windows primary must be pipx"
        for marker in INSTALLER_MARKERS:
            assert marker not in content, f"{rel}: {marker} must not appear on a primary surface"

    # Secondary files: any installer mention needs an unavailability marker,
    # and pipx must still appear earlier in the file (pipx stays primary).
    for path in SECONDARY_WORKFLOW_FILES:
        lines = _lines(path)
        rel = path.relative_to(ROOT).as_posix()
        pipx_index = _line_index(lines, "pipx install licenselens")
        assert pipx_index is not None, f"{rel}: pipx primary must be present"
        content = _read(path)
        for marker in INSTALLER_MARKERS:
            occurrence = _line_index(lines, marker)
            if occurrence is None:
                continue
            assert any(unavailable in content for unavailable in UNAVAILABILITY_MARKERS), (
                f"{rel}: {marker} appears without an unavailability marker"
            )
            assert pipx_index < occurrence, f"{rel}: pipx must appear earlier than {marker}"


def test_operator_surfaces_exclude_contributor_steps() -> None:
    # README quick start section only (## Quick start .. next ## heading).
    readme_lines = _lines(README)
    start = _line_index(readme_lines, "## Quick start")
    assert start is not None, "README.md is missing the ## Quick start section"
    end = next(
        (i for i in range(start + 1, len(readme_lines)) if readme_lines[i].startswith("## ")),
        len(readme_lines),
    )
    quick_start = "\n".join(readme_lines[start:end])
    for step in CONTRIBUTOR_STEPS:
        assert step not in quick_start, f"README.md quick start contains contributor step {step!r}"

    # Remaining operator surfaces are free of contributor steps entirely.
    for path in (DOCS / "index.md", DOCS / "package-readme.md"):
        content = _read(path)
        rel = path.relative_to(ROOT).as_posix()
        for step in CONTRIBUTOR_STEPS:
            assert step not in content, f"{rel} contains contributor step {step!r}"

    # getting-started.md: contributor steps live only inside the contributor tab.
    gs_lines = _lines(DOCS / "getting-started.md")
    tab_index = _line_index(gs_lines, '=== "pip (Contributors only)"')
    assert tab_index is not None, "docs/getting-started.md lost the contributor-tab marker"
    for step in CONTRIBUTOR_STEPS:
        first = _line_index(gs_lines, step)
        assert first is not None, (
            f"docs/getting-started.md should still show {step!r} in the contributor tab"
        )
        assert tab_index < first, (
            f"docs/getting-started.md has {step!r} outside the contributor tab"
        )


def test_no_invented_release_assets() -> None:
    for path in _scanned_docs():
        content = _read(path)
        rel = path.relative_to(ROOT).as_posix()
        for term in INVENTED_ASSET_TERMS:
            assert term.lower() not in content.lower(), (
                f"{rel} mentions invented asset term {term!r}"
            )
        assert not WINDOWS_X64_LITERAL.search(content), (
            f"{rel} contains a hardcoded windows-x64 release zip literal"
        )


def test_windows_release_workflow_promises() -> None:
    content = _read(DOCS / "windows.md")
    required = (
        "-ReleaseBaseUrl",
        "Never run",
        "irm",
        "test-only",
        "not production",
        "signed/promotable",
        "not yet available",
        "github.com/d4rk-pri0r/licenselens/releases/download/",
    )
    for needle in required:
        assert needle in content, f"docs/windows.md is missing release-workflow promise {needle!r}"


def test_no_irm_iex_recommendation_in_docs() -> None:
    for path in (
        README,
        DOCS / "windows.md",
        DOCS / "getting-started.md",
        DOCS / "package-readme.md",
    ):
        offenders = no_irm_iex_recommendation(_read(path))
        rel = path.relative_to(ROOT).as_posix()
        assert not offenders, f"{rel} recommends irm|iex: {offenders}"


def test_no_repo_relative_paths_in_operator_surfaces() -> None:
    for path in (
        README,
        DOCS / "index.md",
        DOCS / "package-readme.md",
        DOCS / "getting-started.md",
    ):
        content = _read(path)
        rel = path.relative_to(ROOT).as_posix()
        for term in REPO_RELATIVE_TERMS:
            assert term not in content, f"{rel} contains repo-relative path {term!r}"


def test_scan_excludes_generated_reference_dir() -> None:
    """The install-path scans must never touch the generated docs/reference/ tree."""
    for path in _scanned_docs():
        assert "reference" not in path.parts, f"{path} unexpectedly scans docs/reference/"
