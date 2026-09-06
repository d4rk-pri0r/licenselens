"""Guard the human-authored docs against stale version/count drift (todo 6, C4).

The authoritative numbers (169 checks, 31 capabilities, 11 profiles, 135 SCuBA
rows, package version 0.4.0) are maintained by hand in a handful of docs files.
This test locks those files to the current values so a stale string (e.g. "140
checks" or "v0.3.0") fails CI instead of shipping.

`docs/reference/*` is generated and already fresh, so it is deliberately
excluded from these scans.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Human-authored docs that carry the authoritative pack numbers. `docs/reference/`
# is generated and fresh, so it is intentionally NOT scanned here.
HUMAN_DOCS = [
    ROOT / "docs" / "index.md",
    ROOT / "docs" / "checks.md",
    ROOT / "docs" / "package-readme.md",
    ROOT / "examples" / "sample-report" / "README.md",
]

# Stale strings that must never reappear in the human-authored docs.
STALE_STRINGS = ["140 declarative", "140 checks", "v0.3.0"]

# Current strings that must be present in the human-authored docs.
CURRENT_STRINGS = ["169"]

# Files that additionally carry the current package version string.
VERSION_DOCS = [
    ROOT / "docs" / "package-readme.md",
    ROOT / "examples" / "sample-report" / "README.md",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_stale_strings_absent_from_human_docs() -> None:
    for path in HUMAN_DOCS:
        content = _read(path)
        for stale in STALE_STRINGS:
            assert stale not in content, f"{path} still contains stale string {stale!r}"


def test_current_strings_present_in_human_docs() -> None:
    for path in HUMAN_DOCS:
        content = _read(path)
        for current in CURRENT_STRINGS:
            assert current in content, f"{path} is missing current string {current!r}"


def test_current_version_present_in_version_docs() -> None:
    for path in VERSION_DOCS:
        content = _read(path)
        assert "0.4.0" in content, f"{path} is missing current version 0.4.0"


def test_support_and_security_pin_current_minor() -> None:
    for path in (ROOT / "docs" / "support.md", ROOT / "docs" / "security.md"):
        content = _read(path)
        assert "0.4.x" in content, f"{path} does not pin the current 0.4.x minor"


def test_releases_has_current_version_heading() -> None:
    content = _read(ROOT / "docs" / "releases.md")
    assert "## [0.4.0]" in content, "docs/releases.md is missing the ## [0.4.0] heading"


def test_scan_excludes_generated_reference_dir() -> None:
    """The freshness scan must never touch the generated docs/reference/ tree."""
    for path in HUMAN_DOCS:
        assert "reference" not in path.parts, f"{path} unexpectedly scans docs/reference/"
