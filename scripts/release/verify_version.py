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


def _minor_line(version: str) -> str:
    """Return the ``MAJOR.MINOR`` line for ``MAJOR.MINOR.PATCH``."""
    parts = version.split(".")
    return ".".join(parts[:2])


def check_docs_coherence(repo_root: Path) -> list[str]:
    """Return violations where public docs describe a different version than the package.

    Audits the surfaces a user of the latest stable package sees for internal
    (product-maturity goal §19) consistency: the PyPI readme, the security and
    support polices, the releases page, and the generated reference manifest.
    Each must refer to the current package version/minor line.
    """
    package_version = version_from_pyproject(repo_root)
    minor = _minor_line(package_version)
    problems: list[str] = []

    def _has(path: str, needle: str) -> bool:
        text = (repo_root / path).read_text(encoding="utf-8")
        return needle in text

    def _has_plain(path: str, needle: str) -> bool:
        text = (repo_root / path).read_text(encoding="utf-8").replace("**", "")
        return needle in text

    # PyPI readme (package-readme.md is the project readme in pyproject.toml).
    if not _has("docs/package-readme.md", f"(v{package_version})"):
        problems.append(
            "docs/package-readme.md does not declare "
            f"(v{package_version}) in its check-pack heading"
        )
    if not _has_plain("docs/package-readme.md", f"package/sample {package_version}"):
        problems.append(
            "docs/package-readme.md check-pack summary does not reference "
            f"package/sample {package_version}"
        )

    # Sample-report README (hand-maintained; must match the current release).
    if not _has_plain("examples/sample-report/README.md", f"package {package_version}"):
        problems.append(
            f"examples/sample-report/README.md does not declare package {package_version}"
        )
    if not _has_plain("examples/sample-report/README.md", "168 checks"):
        problems.append(
            "examples/sample-report/README.md check-pack summary does not reference 168 checks"
        )

    # Security / support policies list the current minor line.
    for policy in ("SECURITY.md", "docs/security.md"):
        if f"{minor}.x" not in _read(repo_root / policy):
            problems.append(
                f"{policy} supported-versions table does not list current line {minor}.x"
            )

    for policy in ("SUPPORT.md", "docs/support.md"):
        if f"{minor}.x" not in _read(repo_root / policy):
            problems.append(
                f"{policy} supported-versions table does not list current line {minor}.x"
            )

    # Releases page has a section for the current version (heading may or may
    # not be bracket-linked; the release tag may not be cut yet, so a tag link
    # must not be required).
    releases_text = _read(repo_root / "docs/releases.md")
    if (
        f"## {package_version}" not in releases_text
        and f"## [{package_version}]" not in releases_text
    ):
        problems.append(f"docs/releases.md has no [{package_version}] release section")

    # Generated reference manifest agrees on the package/sample versions.
    manifest_path = repo_root / "docs" / "reference" / "manifest.json"
    try:
        import json

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        problems.append("docs/reference/manifest.json is missing or not valid JSON")
        return problems
    if manifest.get("package_version") != package_version:
        problems.append(
            "docs/reference/manifest.json package_version "
            f"{manifest.get('package_version')!r} != {package_version!r}"
        )
    if manifest.get("sample_version") != package_version:
        problems.append(
            "docs/reference/manifest.json sample_version "
            f"{manifest.get('sample_version')!r} != {package_version!r}"
        )

    return problems


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def check_tree() -> int:
    """Pre-release path: pyproject, ``__init__``, CHANGELOG, and public docs agree."""
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
    problems.extend(check_docs_coherence(REPO_ROOT))
    if problems:
        for problem in problems:
            print(f"version mismatch: {problem}", file=sys.stderr)
        return 1
    print(
        "tree version consistent: pyproject == __init__ == CHANGELOG "
        f"== public docs == {package_version!r}"
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
