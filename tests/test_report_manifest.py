from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from licenselens.report.html import write_html_report
from licenselens.report.manifest import (
    ASSET_DIRNAME,
    ENTRY_FILENAME,
    BundleFile,
    BundleManifest,
    BundlePathError,
    escape_data_js,
    write_report_bundle,
)
from tests.report_fixtures import comprehensive_report


def _fixture_files() -> tuple[BundleFile, ...]:
    return (
        BundleFile("app.css", b"body{color:#123456}\n", "text/css", "style"),
        BundleFile("app.js", b"globalThis.LicenseLensReady=true;\n", "text/javascript", "script"),
        BundleFile(
            "report-data.js",
            escape_data_js("</script><img src=x onerror=alert(1)> & \u2028 \u2029").encode(),
            "text/javascript",
            "data",
        ),
        BundleFile(
            "icon-entra-id.svg",
            b"<svg xmlns='http://www.w3.org/2000/svg'/>",
            "image/svg+xml",
            "image",
        ),
    )


def _zip_bytes(path: Path) -> bytes:
    return path.read_bytes()


def _manifest(bundle_root: Path) -> BundleManifest:
    manifest_path = bundle_root / ASSET_DIRNAME / "manifest.json"
    manifest: BundleManifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return manifest


def test_bundle_builds_byte_identical_archives_when_fixture_repeats(tmp_path: Path) -> None:
    # Given: the same offline report bundle inputs are built in two clean directories.
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"

    # When: each bundle is written with deterministic archive metadata.
    first = write_report_bundle(first_root, "<main>fixture</main>", _fixture_files())
    second = write_report_bundle(second_root, "<main>fixture</main>", _fixture_files())

    # Then: the zip bytes, member order, and timestamps are stable.
    assert _zip_bytes(first.archive_path) == _zip_bytes(second.archive_path)
    with zipfile.ZipFile(first.archive_path) as archive:
        names = archive.namelist()
        timestamps = {info.date_time for info in archive.infolist()}
    assert names == sorted(names)
    assert timestamps == {(1980, 1, 1, 0, 0, 0)}


def test_bundle_manifest_freezes_entry_assets_and_mime_metadata(tmp_path: Path) -> None:
    # Given: CSS, JS, and data JS files for an offline report bundle.
    bundle_root = tmp_path / "bundle"

    # When: the bundle contract helper writes the fixture.
    bundle = write_report_bundle(bundle_root, "<main>fixture</main>", _fixture_files())

    # Then: legacy entry, sibling asset directory, hashes, and MIME/type metadata exist.
    assert bundle.entry_path == bundle_root / ENTRY_FILENAME
    assert bundle.entry_path.read_text(encoding="utf-8") == "<main>fixture</main>"
    assert bundle.assets_dir == bundle_root / ASSET_DIRNAME
    manifest = _manifest(bundle_root)
    assert manifest["entry"] == ENTRY_FILENAME
    assert manifest["assets_dir"] == ASSET_DIRNAME
    assert manifest["network"] == "none"
    files = manifest["files"]
    assert isinstance(files, list)
    assert [file["kind"] for file in files] == ["style", "script", "data", "image"]
    assert {file["media_type"] for file in files} == {
        "text/css",
        "text/javascript",
        "image/svg+xml",
    }
    assert all(str(file["path"]).startswith(f"{ASSET_DIRNAME}/") for file in files)
    assert all("-" in Path(str(file["path"])).stem for file in files)
    assert (bundle_root / ASSET_DIRNAME / "manifest.json").is_file()


def test_bundle_references_stay_inside_bundle(tmp_path: Path) -> None:
    # Given: a bundle manifest with content-hashed asset references.
    bundle_root = tmp_path / "bundle"

    # When: the bundle is written.
    write_report_bundle(bundle_root, "<main>fixture</main>", _fixture_files())

    # Then: every manifest file reference resolves under the bundle root.
    root = bundle_root.resolve()
    manifest = _manifest(bundle_root)
    files = manifest["files"]
    assert isinstance(files, list)
    for file in files:
        resolved = (bundle_root / str(file["path"])).resolve()
        assert resolved.is_relative_to(root)


def test_bundle_rejects_path_traversal_and_symlink_members(tmp_path: Path) -> None:
    # Given: malicious member paths and a symlink inside the assets directory.
    traversal = BundleFile("../escape.js", b"alert(1)", "text/javascript", "script")
    symlink_root = tmp_path / "symlink"
    assets_dir = symlink_root / ASSET_DIRNAME
    assets_dir.mkdir(parents=True)
    (assets_dir / "linked.js").symlink_to(tmp_path / "outside.js")
    symlink = BundleFile("linked.js", b"alert(1)", "text/javascript", "script")

    # When / Then: traversal and symlink targets are rejected before archive writing.
    with pytest.raises(BundlePathError):
        write_report_bundle(tmp_path / "traversal", "<main>fixture</main>", (traversal,))
    with pytest.raises(BundlePathError):
        write_report_bundle(symlink_root, "<main>fixture</main>", (symlink,))


def test_data_js_escape_contract_blocks_script_terminators_and_line_separators() -> None:
    # Given: JSON-bearing data that can break out of a script tag if left raw.
    dangerous = "<script></script><ScRiPt>&\u2028\u2029"

    # When: it is escaped for data JS embedding.
    escaped = escape_data_js(dangerous)

    # Then: HTML-sensitive bytes, script terminators, and JS line separators are escaped.
    assert "<" not in escaped
    assert ">" not in escaped
    assert "&" not in escaped
    assert "</script" not in escaped.lower()
    assert "\u2028" not in escaped
    assert "\u2029" not in escaped
    assert "\\u003cscript\\u003e" in escaped.lower()
    assert "\\u2028" in escaped
    assert "\\u2029" in escaped


def test_legacy_html_writer_still_returns_path_and_entry_filename_is_stable(tmp_path: Path) -> None:
    # Given: the historical report entry path used by CLI and batch outputs.
    entry = tmp_path / ENTRY_FILENAME

    # When: the existing HTML writer renders a report.
    written = write_html_report(comprehensive_report(), entry)

    # Then: write_html_report keeps returning the same Path and filename contract.
    assert written == entry
    assert written.name == "security-license-lens-report.html"
    assert written.is_file()
