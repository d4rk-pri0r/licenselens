"""Release gate: fail when the release tag does not match the package version.

Usage::

    python scripts/release/verify_version.py [<tag>]

With a ``<tag>`` argument (the release workflow path), reads
``[project].version`` from ``pyproject.toml`` and compares it to the tag
(stripping a leading ``v``). Exits 0 on match, 1 on mismatch. This runs in the
``build`` job of the release workflow so a mis-tagged release is rejected before
any artifact is published, and never relies on the package being installed.

Without a tag (the pre-release consistency path, used while no tag exists yet),
it validates the tree alone: ``pyproject.toml``, ``src/licenselens/__init__.py``,
and the CHANGELOG's top version heading must all agree on the same version.
This checks the same single source of truth the tag check enforces, so a future
``v<version>`` tag is guaranteed to pass. Exits 0 when all three agree, 1 on
any mismatch, 2 on a usage error.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(REPO_ROOT / "src"))

from licenselens.release_guard import normalize_tag, version_from_pyproject  # noqa: E402


def version_from_init(repo_root: Path) -> str:
    """Return the ``__version__`` string from ``src/licenselens/__init__.py``."""
    text = (repo_root / "src" / "licenselens" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"\s*$', text, re.MULTILINE)
    if not match:
        raise ValueError("src/licenselens/__init__.py is missing a __version__ string")
    return match.group(1)


def changelog_top_version(repo_root: Path) -> str | None:
    """Return the version of the CHANGELOG's top ``## [...]`` heading.

    Returns ``None`` when the top section is still ``[Unreleased]`` (the release
    line has not been cut yet) or when no version heading exists at all.
    """
    text = (repo_root / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(r"^## \[([^\]]+)\]", text, re.MULTILINE)
    if not match:
        return None
    heading = match.group(1)
    return None if heading == "Unreleased" else heading


def check_tag(tag: str) -> int:
    """Release path: the tag (leading ``v`` stripped) must equal the pyproject version."""
    package_version = version_from_pyproject(REPO_ROOT)
    if normalize_tag(tag) != package_version:
        print(
            f"version mismatch: tag {tag!r} -> {normalize_tag(tag)!r} "
            f"!= pyproject.toml version {package_version!r}",
            file=sys.stderr,
        )
        return 1
    print(f"version consistent: tag {tag!r} == package {package_version!r}")
    return 0


def check_tree() -> int:
    """Pre-release path: pyproject, ``__init__``, and the CHANGELOG must agree."""
    package_version = version_from_pyproject(REPO_ROOT)
    init_version = version_from_init(REPO_ROOT)
    changelog_version = changelog_top_version(REPO_ROOT)
    problems: list[str] = []
    if init_version != package_version:
        problems.append(
            f"__init__.__version__ {init_version!r} != pyproject.toml version {package_version!r}"
        )
    if changelog_version is None:
        problems.append(
            "CHANGELOG.md has no released version heading (top section is [Unreleased])"
        )
    elif changelog_version != package_version:
        problems.append(
            f"CHANGELOG.md top version {changelog_version!r} "
            f"!= pyproject.toml version {package_version!r}"
        )
    if problems:
        for problem in problems:
            print(f"version mismatch: {problem}", file=sys.stderr)
        return 1
    print(
        f"tree version consistent: pyproject == __init__ == CHANGELOG == {package_version!r}"
    )
    return 0


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print("usage: verify_version.py [<tag>]", file=sys.stderr)
        return 2
    if len(argv) == 2:
        return check_tag(argv[1])
    return check_tree()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
