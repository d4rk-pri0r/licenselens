"""Lock the honest publication-status wording across the public docs.

PyPI serves 0.3.0 while the tree carries 0.4.0 (in-tree, pending
publication). While that is true, every public surface must say so. Once a
published PyPI version reaches the tree version (the human-gated HG1 ship),
the pending wording must be removed — this test is the CI-enforced flip for
that post-ship wording change.

The live comparison reads the real PyPI JSON index. When the network is
unavailable the live check skips with an explicit reason (visible in the
pytest summary) — it never silently passes; the static wording locks below
always run.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from packaging.version import InvalidVersion, Version

import licenselens

ROOT = Path(__file__).resolve().parents[1]

PYPI_JSON_URL = "https://pypi.org/pypi/licenselens/json"
PYPI_TIMEOUT_S = 10

# The pending-publication wording each surface must carry while PyPI lags the
# tree, and the README/package-readme parenthetical on the wheel claim.
RELEASES_STATUS_PENDING = "not yet published to PyPI (PyPI latest: 0.3.0)"
CHANGELOG_STATUS_PENDING = "not yet published to PyPI (PyPI latest: 0.3.0)"
WHEEL_CLAIM = "bundles the PowerShell collector bridge since 0.4.0"
PENDING_PARENTHETICAL = (
    "(shipping in the 0.4.0 release; PyPI latest is 0.3.0 until it is published"
)

# Surfaces checked by the live PyPI comparison: (path, pending marker).
PENDING_SURFACES = [
    (ROOT / "docs" / "releases.md", RELEASES_STATUS_PENDING),
    (ROOT / "CHANGELOG.md", CHANGELOG_STATUS_PENDING),
    (ROOT / "README.md", PENDING_PARENTHETICAL),
    (ROOT / "docs" / "package-readme.md", PENDING_PARENTHETICAL),
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _normalized(text: str) -> str:
    """Collapse whitespace so wrapped markdown lines match as one string."""
    return re.sub(r"\s+", " ", text)


def _section(text: str, heading: str) -> str:
    """Return the body of the ``<heading>`` section (up to the next ``## ``)."""
    after = text.split(heading, 1)[1]
    return after.split("\n## ", 1)[0]


def test_releases_page_states_publication_status() -> None:
    text = _read(ROOT / "docs" / "releases.md")
    # The heading must stay byte-identical (verify_version docs coherence).
    assert "## [0.4.0] — 2026-08-16" in text
    section = _normalized(_section(text, "## [0.4.0]"))
    assert RELEASES_STATUS_PENDING in section, (
        "docs/releases.md 0.4.0 section is missing the publication-status line "
        "mentioning PyPI latest 0.3.0"
    )


def test_changelog_states_publication_status() -> None:
    text = _read(ROOT / "CHANGELOG.md")
    assert "## [0.4.0] — 2026-08-16" in text
    section = _normalized(_section(text, "## [0.4.0]"))
    assert CHANGELOG_STATUS_PENDING in section, (
        "CHANGELOG.md 0.4.0 section is missing the pending-publication status line"
    )


@pytest.mark.parametrize("path", [ROOT / "README.md", ROOT / "docs" / "package-readme.md"])
def test_wheel_claim_carries_pending_parenthetical(path: Path) -> None:
    text = _normalized(_read(path))
    assert WHEEL_CLAIM in text, f"{path} is missing the wheel claim sentence"
    assert PENDING_PARENTHETICAL in text, (
        f"{path} wheel claim is missing the pending-publication parenthetical"
    )


def _pypi_max_version() -> Version | None:
    """Return the max published version on PyPI, or None when unreachable."""
    try:
        with urllib.request.urlopen(PYPI_JSON_URL, timeout=PYPI_TIMEOUT_S) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None
    published: list[Version] = []
    for key in data.get("releases", {}):
        try:
            published.append(Version(key))
        except InvalidVersion:
            continue
    return max(published) if published else None


def test_pypi_publication_status_matches_docs() -> None:
    """The docs flip exactly when PyPI catches up to the tree version.

    While PyPI's max published version is older than ``licenselens.__version__``
    the pending wording MUST be present; once PyPI serves at least the tree
    version it MUST be gone. Network-unreachable skips loudly — never silently
    passes.
    """
    tree_version = Version(licenselens.__version__)
    published = _pypi_max_version()
    if published is None:
        pytest.skip(
            "live PyPI check NOT RUN: "
            f"{PYPI_JSON_URL} unreachable (network unavailable or invalid response)"
        )
    still_pending = [
        str(path.relative_to(ROOT))
        for path, marker in PENDING_SURFACES
        if marker in _normalized(_read(path))
    ]
    if published < tree_version:
        absent = [
            str(path.relative_to(ROOT))
            for path, marker in PENDING_SURFACES
            if str(path.relative_to(ROOT)) not in still_pending
        ]
        assert not absent, (
            f"PyPI serves {published} < tree {tree_version}, so every public "
            f"surface must carry the pending-publication wording; missing from: {absent}"
        )
    else:
        assert not still_pending, (
            f"PyPI serves {published} >= tree {tree_version}: the "
            "pending-publication wording must be removed (HG1 post-ship flip); "
            f"still present in: {still_pending}"
        )
