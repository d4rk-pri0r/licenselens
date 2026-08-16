"""Deterministic offline report bundle generation and safe archive delivery.

``manifest.py`` freezes the on-disk bundle contract (entry filename, sibling
assets directory, content-hashed assets, deterministic ZIP). This module is the
report-side orchestration layer: it renders the ``file://``-openable entry from
the versioned ``report_app`` templates, serializes the scan data into an escaped
data JS asset, and hands the resulting ``BundleFile`` set to ``write_report_bundle``.

The versioned app assets live under ``templates/report_app/v<N>/`` and are
resolved through ``licenselens.paths`` so they ship in the wheel and PyInstaller
data without any filesystem assumption.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from licenselens.catalog.expected_states import expected_state_map
from licenselens.models import ScanResult
from licenselens.paths import templates_dir
from licenselens.report.html import build_report_context, report_environment
from licenselens.report.icons import icon_bundle_files, workload_icon_urls
from licenselens.report.manifest import (
    ASSET_DIRNAME,
    MANIFEST_FILENAME,
    BundleFile,
    ReportBundle,
    escape_data_js,
    write_report_bundle,
)
from licenselens.report.viewmodel import build_constellation, build_sections

REPORT_APP_VERSION: Final = "2"
DATA_JS_GLOBAL: Final = "window.LICENSELENS_REPORT_JSON"
ICONS_JS_GLOBAL: Final = "window.LICENSELENS_WORKLOAD_ICONS"
VIEWMODEL_JS_GLOBAL: Final = "window.LICENSELENS_VIEWMODEL"

_CSS_LOGICAL: Final = "app.css"
_JS_LOGICAL: Final = "app.js"
_DATA_LOGICAL: Final = "report-data.js"


@dataclass(frozen=True, slots=True)
class ReportBundleError(Exception):
    diagnostic: str

    def __str__(self) -> str:
        return self.diagnostic


def build_report_bundle(result: ScanResult, output_dir: Path) -> ReportBundle:
    """Render and write a complete deterministic offline report bundle."""
    css = _read_asset(f"report_app/v{REPORT_APP_VERSION}/{_CSS_LOGICAL}")
    js = _read_asset(f"report_app/v{REPORT_APP_VERSION}/{_JS_LOGICAL}")
    image_files = icon_bundle_files()
    icon_urls = workload_icon_urls(image_files)
    expected_by_check_id = expected_state_map()
    data_js = _serialize_data_js(result, icon_urls, expected_by_check_id)

    css_name = _hashed_asset_name(_CSS_LOGICAL, css)
    js_name = _hashed_asset_name(_JS_LOGICAL, js)
    data_name = _hashed_asset_name(_DATA_LOGICAL, data_js)

    context = build_report_context(result, expected_by_check_id)
    context.update(
        assets_dir=ASSET_DIRNAME,
        css_name=css_name,
        js_name=js_name,
        data_name=data_name,
        workload_icon_urls=icon_urls,
    )
    entry_html = report_environment().get_template("report_app/entry.html.j2").render(**context)

    return write_report_bundle(
        output_dir,
        entry_html,
        (
            BundleFile(_CSS_LOGICAL, css, "text/css", "style"),
            BundleFile(_JS_LOGICAL, js, "text/javascript", "script"),
            BundleFile(_DATA_LOGICAL, data_js, "text/javascript", "data"),
            *image_files,
        ),
    )


def verify_report_bundle(root: Path) -> list[str]:
    """Return a list of integrity problems; an empty list means the bundle is intact."""
    problems: list[str] = []
    manifest_path = root / ASSET_DIRNAME / MANIFEST_FILENAME
    if not manifest_path.is_file():
        return [f"missing manifest: {MANIFEST_FILENAME}"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"unreadable manifest: {exc}"]
    if not isinstance(manifest, dict):
        return ["manifest is not a JSON object"]

    entry_name = manifest.get("entry")
    if not isinstance(entry_name, str) or not _is_safe_relative(entry_name):
        problems.append(f"invalid entry reference: {entry_name!r}")
    elif not (root / entry_name).is_file():
        problems.append(f"missing entry: {entry_name!r}")

    files = manifest.get("files")
    if not isinstance(files, list):
        return [*problems, "manifest has no files list"]
    for file in files:
        if not isinstance(file, dict):
            problems.append("manifest file entry is not a mapping")
            continue
        rel = file.get("path")
        if not isinstance(rel, str) or not _is_safe_relative(rel):
            problems.append(f"invalid asset reference: {rel!r}")
            continue
        asset = root / rel
        if not asset.is_file():
            problems.append(f"missing asset: {rel}")
            continue
        actual = _sha256(asset.read_bytes())
        if actual != file.get("sha256"):
            problems.append(f"hash mismatch for {rel}")
    return problems


def extract_report_archive(archive_path: Path, destination: Path) -> Path:
    """Extract a report archive, rejecting traversal and symlink members."""
    destination.mkdir(parents=True, exist_ok=True)
    resolved_root = destination.resolve()
    with zipfile.ZipFile(archive_path, "r") as archive:
        for member in archive.infolist():
            _validate_archive_member(member.filename)
            if _is_symlink_member(member):
                raise ReportBundleError(f"symlink archive member is not allowed: {member.filename}")
            target = (destination / member.filename).resolve()
            if not target.is_relative_to(resolved_root):
                raise ReportBundleError(f"archive member escapes destination: {member.filename}")
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(member))
    return resolved_root


def _read_asset(relative_name: str) -> bytes:
    path = templates_dir() / relative_name
    if not path.is_file():
        raise ReportBundleError(f"report app asset not found: {relative_name}")
    return path.read_bytes()


def _serialize_data_js(
    result: ScanResult,
    icon_urls: dict[str, str],
    expected_by_check_id: dict[str, str],
) -> bytes:
    payload = json.dumps(
        result.model_dump(mode="json"),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    icons = json.dumps(icon_urls, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    # build_sections returns ``C`` as ``result.moves`` (list[TopMove]); serialize
    # those models so the view-model payload is a pure JSON value.
    sections = build_sections(result, expected_by_check_id)
    sections["C"] = [move.model_dump(mode="json") for move in result.moves]
    viewmodel = json.dumps(
        {"sections": sections, "constellation": build_constellation(result)},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return (
        f"{ICONS_JS_GLOBAL} = {escape_data_js(icons)};\n"
        f"{DATA_JS_GLOBAL} = {escape_data_js(payload)};\n"
        f"{VIEWMODEL_JS_GLOBAL} = {escape_data_js(viewmodel)};\n"
    ).encode()


def _hashed_asset_name(logical_name: str, content: bytes) -> str:
    path = PurePosixPath(logical_name)
    return f"{path.stem}-{_sha256(content)[:16]}{path.suffix}"


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _is_safe_relative(name: str) -> bool:
    try:
        _validate_archive_member(name)
    except ReportBundleError:
        return False
    return True


def _validate_archive_member(name: str) -> None:
    if "\\" in name:
        raise ReportBundleError(f"invalid archive member {name!r}: backslash separators")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ReportBundleError(f"archive member escapes the bundle: {name!r}")


def _is_symlink_member(member: zipfile.ZipInfo) -> bool:
    return ((member.external_attr >> 16) & 0o170000) == 0o120000
