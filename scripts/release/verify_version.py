"""Release gate: fail when the release tag does not match the package version.

Usage::

    python scripts/release/verify_version.py <tag>

Reads ``[project].version`` from ``pyproject.toml`` and compares it to the tag
(stripping a leading ``v``). Exits 0 on match, 1 on mismatch. This runs in the
``build`` job of the release workflow so a mis-tagged release is rejected before
any artifact is published, and never relies on the package being installed.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(REPO_ROOT / "src"))

from licenselens.release_guard import normalize_tag, version_from_pyproject  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: verify_version.py <tag>", file=sys.stderr)
        return 2
    tag = argv[1]
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


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
