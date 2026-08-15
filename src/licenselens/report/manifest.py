from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, Literal, TypedDict

ENTRY_FILENAME: Final = "security-license-lens-report.html"
ASSET_DIRNAME: Final = "security-license-lens-report.assets"
MANIFEST_FILENAME: Final = "manifest.json"
ZIP_TIMESTAMP: Final = (1980, 1, 1, 0, 0, 0)

type BundleFileKind = Literal["style", "script", "data", "image"]


@dataclass(frozen=True, slots=True)
class BundlePathError(Exception):
    path: str
    reason: str

    def __str__(self) -> str:
        return f"invalid bundle path {self.path!r}: {self.reason}"


@dataclass(frozen=True, slots=True)
class BundleFile:
    logical_name: str
    content: bytes
    media_type: str
    kind: BundleFileKind


@dataclass(frozen=True, slots=True)
class ReportBundle:
    root: Path
    entry_path: Path
    assets_dir: Path
    manifest_path: Path
    archive_path: Path


class ManifestFile(TypedDict):
    path: str
    sha256: str
    bytes: int
    media_type: str
    kind: BundleFileKind


class BundleManifest(TypedDict):
    version: str
    entry: str
    assets_dir: str
    network: str
    files: list[ManifestFile]


def escape_data_js(value: str) -> str:
    return (
        value.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def write_report_bundle(root: Path, entry_html: str, files: tuple[BundleFile, ...]) -> ReportBundle:
    root.mkdir(parents=True, exist_ok=True)
    _reject_existing_symlinks(root)
    assets_dir = root / ASSET_DIRNAME
    assets_dir.mkdir(exist_ok=True)

    entry_path = root / ENTRY_FILENAME
    _reject_existing_symlink(entry_path, ENTRY_FILENAME)
    entry_path.write_text(entry_html, encoding="utf-8")

    manifest_files: list[ManifestFile] = []
    for file in files:
        asset_name = _hashed_asset_name(file)
        asset_relative_path = f"{ASSET_DIRNAME}/{asset_name}"
        _validate_relative_bundle_path(asset_relative_path)
        asset_path = root / asset_relative_path
        _reject_existing_symlink(asset_path, asset_relative_path)
        asset_path.write_bytes(file.content)
        manifest_files.append(
            {
                "path": asset_relative_path,
                "sha256": _sha256(file.content),
                "bytes": len(file.content),
                "media_type": file.media_type,
                "kind": file.kind,
            }
        )

    manifest_path = assets_dir / MANIFEST_FILENAME
    _reject_existing_symlink(manifest_path, f"{ASSET_DIRNAME}/{MANIFEST_FILENAME}")
    manifest = BundleManifest(
        version="1",
        entry=ENTRY_FILENAME,
        assets_dir=ASSET_DIRNAME,
        network="none",
        files=manifest_files,
    )
    manifest_path.write_text(_manifest_json(manifest), encoding="utf-8")

    archive_path = root / "security-license-lens-report.zip"
    _write_deterministic_zip(root, archive_path)
    return ReportBundle(root, entry_path, assets_dir, manifest_path, archive_path)


def _hashed_asset_name(file: BundleFile) -> str:
    logical_path = _validate_logical_asset_name(file.logical_name)
    digest = _sha256(file.content)[:16]
    return f"{logical_path.stem}-{digest}{logical_path.suffix}"


def _validate_logical_asset_name(value: str) -> PurePosixPath:
    if "\\" in value:
        raise BundlePathError(value, "backslash separators are not allowed")
    path = PurePosixPath(value)
    if path.is_absolute() or path.name != value or path.name in {"", ".", ".."}:
        raise BundlePathError(value, "asset names must be plain relative filenames")
    return path


def _validate_relative_bundle_path(value: str) -> None:
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise BundlePathError(value, "bundle paths must stay inside the report bundle")


def _reject_existing_symlink(path: Path, relative_path: str) -> None:
    if path.is_symlink():
        raise BundlePathError(relative_path, "symlink bundle members are not allowed")


def _reject_existing_symlinks(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            raise BundlePathError(
                path.relative_to(root).as_posix(), "symlink bundle members are not allowed"
            )


def _manifest_json(manifest: BundleManifest) -> str:
    return json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _write_deterministic_zip(root: Path, archive_path: Path) -> None:
    members = sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path != archive_path and not path.is_symlink()
    )
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
        for member in members:
            relative_name = member.relative_to(root).as_posix()
            _validate_relative_bundle_path(relative_name)
            info = zipfile.ZipInfo(relative_name, ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, member.read_bytes())
