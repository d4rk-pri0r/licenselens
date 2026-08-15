"""Release artifact: dependency/license inventory.

Usage::

    python scripts/release/license_inventory.py --output dist/license-inventory.json

Enumerates the direct runtime dependencies from ``pyproject.toml`` and, for each
one that is importable in the build environment, records its resolved version and
declared license from package metadata (``importlib.metadata``). The output is a
deterministic, sorted JSON object plus a Markdown summary, shipped alongside the
release so every artifact discloses its dependency/license surface.
"""

from __future__ import annotations

import argparse
import json
import sys
from importlib import metadata
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(REPO_ROOT / "src"))

from licenselens.release_guard import direct_dependencies  # noqa: E402

#: License classifiers worth surfacing from distribution metadata.
_LICENSE_PREFIX = "License :: OSI Approved :: "


def _dist_license(dist: metadata.Distribution) -> str:
    raw = None
    try:
        raw = dist.metadata.get("License-Expression") or dist.metadata.get("License")
    except Exception:  # pragma: no cover - defensive against odd metadata
        raw = None
    if not raw:
        for classifier in dist.metadata.get_all("Classifier", []):
            if classifier.startswith(_LICENSE_PREFIX):
                raw = classifier[len(_LICENSE_PREFIX) :]
                break
    return raw or "unknown"


def build_inventory(repo_root: Path) -> dict:
    entries = []
    for name, specifier in direct_dependencies(repo_root / "pyproject.toml"):
        resolved_version: str | None = None
        license_name = "unknown"
        try:
            dist = metadata.distribution(name)
            resolved_version = dist.version
            license_name = _dist_license(dist)
        except metadata.PackageNotFoundError:
            pass
        entries.append(
            {
                "name": name,
                "specifier": specifier,
                "resolved_version": resolved_version,
                "license": license_name,
            }
        )
    entries.sort(key=lambda e: e["name"])
    return {
        "schema_version": 1,
        "package": "licenselens",
        "package_version": _package_version(repo_root),
        "dependencies": entries,
    }


def _package_version(repo_root: Path) -> str:
    from licenselens.release_guard import version_from_pyproject

    return version_from_pyproject(repo_root)


def _render_markdown(inventory: dict) -> str:
    lines = [
        "# Third-party dependencies",
        "",
        f"LicenseLens {inventory['package_version']} — direct runtime dependencies.",
        "",
        "| Package | Specifier | Resolved | License |",
        "|---------|-----------|----------|---------|",
    ]
    for dep in inventory["dependencies"]:
        resolved = dep["resolved_version"] or "(not installed)"
        lines.append(f"| {dep['name']} | `{dep['specifier']}` | {resolved} | {dep['license']} |")
    lines.append("")
    lines.append(
        "Resolved versions/licenses reflect the build environment; the committed "
        "`THIRD_PARTY_NOTICES.md` records the declared direct-dependency licenses."
    )
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Generate the dependency/license inventory.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("dist/license-inventory.json"),
        help="JSON output path (default: dist/license-inventory.json)",
    )
    args = parser.parse_args(argv)

    inventory = build_inventory(REPO_ROOT)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path = args.output.with_suffix(".md")
    markdown_path.write_text(_render_markdown(inventory), encoding="utf-8")

    print(f"license inventory written to {args.output}")
    print(f"markdown summary written to {markdown_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
