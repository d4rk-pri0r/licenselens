"""Pinned Microsoft workload icon allowlist (vendored, offline).

Validates ``assets/vendor/microsoft-cloud/manifest.yaml`` against on-disk
bytes. Assets are never hotlinked at runtime; only local paths are used.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

import yaml

from licenselens.paths import _repo_root

PINNED_UPSTREAM_COMMIT: Final = "fc3a6c9506dc9a6ebdfb4f5891ee486f2717257c"
UPSTREAM_REPO: Final = "loryanstrant/MicrosoftCloudLogos"
VENDOR_REL: Final = Path("assets/vendor/microsoft-cloud")
MANIFEST_NAME: Final = "manifest.yaml"
EXPECTED_ASSET_COUNT: Final = 12
SHA256_RE: Final = re.compile(r"^[a-f0-9]{64}$")

# Path segments / tokens that must never appear in allowlisted assets.
_FORBIDDEN_PATH_TOKENS: Final = frozenset(
    {
        "unofficial",
        "legacy",
        "corporate",
        "flagship",
        "lockup",
        "former",
    }
)

_ASSET_LIST_KEYS: Final = ("assets", "files", "icons", "entries")


def vendor_root(repo_root: Path | None = None) -> Path:
    root = repo_root if repo_root is not None else _repo_root()
    if root is None:
        raise FileNotFoundError("cannot resolve repository root for vendor assets")
    return root / VENDOR_REL


def manifest_path(repo_root: Path | None = None) -> Path:
    return vendor_root(repo_root) / MANIFEST_NAME


def _asset_entries(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    for key in _ASSET_LIST_KEYS:
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _entry_path(entry: Mapping[str, Any]) -> str:
    return str(entry.get("path") or entry.get("file") or entry.get("name") or "").strip()


def _entry_sha(entry: Mapping[str, Any]) -> str:
    return str(
        entry.get("sha256") or entry.get("sha256_hex") or entry.get("digest") or ""
    ).strip().lower()


def _entry_commit(entry: Mapping[str, Any], default: str | None) -> str | None:
    raw = entry.get("commit") or entry.get("upstream_commit") or default
    return str(raw) if raw is not None else None


def _upstream_commit(data: Mapping[str, Any]) -> str | None:
    upstream = (
        data.get("upstream_commit")
        or data.get("source_commit")
        or data.get("commit")
    )
    if upstream is None:
        nested = data.get("upstream")
        if isinstance(nested, Mapping):
            upstream = nested.get("commit")
    return str(upstream) if upstream is not None else None


def _path_is_forbidden(rel: str) -> list[str]:
    problems: list[str] = []
    lowered = rel.lower().replace("\\", "/")
    parts = Path(lowered).parts
    for token in _FORBIDDEN_PATH_TOKENS:
        if token in parts or token in lowered:
            problems.append(f"asset path rejected ({token}): {rel}")
    return problems


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_manifest(
    data: Mapping[str, Any],
    *,
    repo_root: Path | None = None,
    check_disk: bool = True,
) -> list[str]:
    """Return a list of problems; empty means the manifest is acceptable.

    Fail-closed on checksum drift, unofficial/legacy path tokens, wrong pin,
    wrong count, and on-disk extras when ``check_disk`` is true.
    """
    problems: list[str] = []
    assets = _asset_entries(data)
    if not assets:
        return ["logo manifest must contain an assets/files list of pinned file entries"]

    upstream = _upstream_commit(data)
    if upstream != PINNED_UPSTREAM_COMMIT:
        problems.append(
            f"manifest upstream commit must be {PINNED_UPSTREAM_COMMIT}, got {upstream!r}"
        )

    if len(assets) != EXPECTED_ASSET_COUNT:
        problems.append(
            f"logo manifest must pin exactly {EXPECTED_ASSET_COUNT} assets, "
            f"got {len(assets)}"
        )

    seen_paths: set[str] = set()
    root = vendor_root(repo_root) if check_disk else None

    for entry in assets:
        rel = _entry_path(entry)
        if not rel:
            problems.append(f"asset entry missing path: {entry!r}")
            continue
        if rel in seen_paths:
            problems.append(f"duplicate asset path: {rel}")
        seen_paths.add(rel)

        problems.extend(_path_is_forbidden(rel))

        sha = _entry_sha(entry)
        if not SHA256_RE.match(sha):
            problems.append(f"asset {rel!r} missing pinned sha256, got {sha!r}")

        entry_commit = _entry_commit(entry, upstream)
        if entry_commit != PINNED_UPSTREAM_COMMIT:
            problems.append(
                f"asset {rel!r} must pin upstream commit {PINNED_UPSTREAM_COMMIT}"
            )

        blob = " ".join(str(v).lower() for v in entry.values())
        if "unofficial" in blob:
            problems.append(f"asset {rel!r} must not use unofficial variant")

        if check_disk and root is not None and SHA256_RE.match(sha):
            on_disk = root / rel
            if not on_disk.is_file():
                problems.append(f"missing vendored file for {rel}")
            else:
                actual = _sha256_file(on_disk)
                if actual != sha:
                    problems.append(
                        f"checksum drift for {rel}: manifest={sha} disk={actual}"
                    )

    if check_disk and root is not None:
        on_disk_files = sorted(
            p.relative_to(root).as_posix()
            for p in root.rglob("*")
            if p.is_file() and p.name != MANIFEST_NAME
        )
        if len(on_disk_files) != EXPECTED_ASSET_COUNT:
            problems.append(
                f"vendor tree must contain exactly {EXPECTED_ASSET_COUNT} asset files, "
                f"got {on_disk_files}"
            )
        extra = sorted(set(on_disk_files) - seen_paths)
        missing = sorted(seen_paths - set(on_disk_files))
        for path in extra:
            problems.append(f"unlisted asset on disk (rejected): {path}")
        for path in missing:
            problems.append(f"manifest path missing on disk: {path}")

    return problems


def verify_assets(
    data: Mapping[str, Any] | None = None,
    *,
    repo_root: Path | None = None,
) -> list[str]:
    """Load the on-disk manifest (if needed) and validate it."""
    if data is None:
        path = manifest_path(repo_root)
        if not path.is_file():
            return [f"missing vendor logo manifest at {path.as_posix()}"]
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, Mapping):
            return ["logo manifest root must be a mapping"]
        data = loaded
    return validate_manifest(data, repo_root=repo_root, check_disk=True)


def load_manifest(repo_root: Path | None = None) -> dict[str, Any]:
    path = manifest_path(repo_root)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("logo manifest root must be a mapping")
    return data


def scan_svg_safety(text: str) -> list[str]:
    """Reject ``<script>`` and external resource URL references in SVG text.

    W3C XML namespace URIs (``http://www.w3.org/...``) on ``xmlns`` attributes
    are allowed; ``href`` / ``xlink:href`` / ``src`` / ``url(http...)`` loads
    are not.
    """
    problems: list[str] = []
    if re.search(r"<\s*script\b", text, flags=re.IGNORECASE):
        problems.append("svg contains <script>")
    for match in re.finditer(
        r"""(?:href|xlink:href|src)\s*=\s*["'](https?://[^"']+)["']""",
        text,
        flags=re.IGNORECASE,
    ):
        problems.append(f"svg external attr URL: {match.group(1)}")
    for match in re.finditer(
        r"""url\(\s*["']?(https?://[^"')\s]+)""",
        text,
        flags=re.IGNORECASE,
    ):
        problems.append(f"svg external css url(): {match.group(1)}")
    return problems


__all__ = [
    "EXPECTED_ASSET_COUNT",
    "PINNED_UPSTREAM_COMMIT",
    "UPSTREAM_REPO",
    "load_manifest",
    "manifest_path",
    "scan_svg_safety",
    "validate_manifest",
    "vendor_root",
    "verify_assets",
]
