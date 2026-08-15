"""Pack pinned Microsoft workload icons into the offline report bundle."""

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
from typing import Final

from licenselens.report.manifest import ASSET_DIRNAME, BundleFile
from licenselens.vendor_assets import REPORT_WORKLOAD_TO_ICON_KEY, load_pinned_icons

_ICON_LOGICAL_PREFIX: Final = "icon-"


def icon_bundle_files() -> tuple[BundleFile, ...]:
    """Return content-hashed-ready image ``BundleFile`` entries (sorted)."""
    files: list[BundleFile] = []
    for icon in load_pinned_icons():
        suffix = PurePosixPath(icon.relative_path).suffix.lower()
        logical = f"{_ICON_LOGICAL_PREFIX}{icon.icon_key}{suffix}"
        files.append(BundleFile(logical, icon.content, icon.media_type, "image"))
    return tuple(sorted(files, key=lambda item: item.logical_name))


def workload_icon_urls(files: tuple[BundleFile, ...]) -> dict[str, str]:
    """Map report workload keys to entry-relative hashed asset paths."""
    icon_key_to_path: dict[str, str] = {}
    for file in files:
        if file.kind != "image":
            continue
        stem = PurePosixPath(file.logical_name).stem
        if not stem.startswith(_ICON_LOGICAL_PREFIX):
            continue
        icon_key = stem.removeprefix(_ICON_LOGICAL_PREFIX)
        digest = hashlib.sha256(file.content).hexdigest()[:16]
        hashed = f"{stem}-{digest}{PurePosixPath(file.logical_name).suffix}"
        icon_key_to_path[icon_key] = f"{ASSET_DIRNAME}/{hashed}"

    urls: dict[str, str] = {}
    for workload, icon_key in sorted(REPORT_WORKLOAD_TO_ICON_KEY.items()):
        path = icon_key_to_path.get(icon_key)
        if path is not None:
            urls[workload] = path
    return urls
