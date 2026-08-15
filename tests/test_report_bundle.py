"""Deterministic offline report bundle tests (Todo 25).

Lock the bundle seam built on ``licenselens.report.manifest``: byte-identical
rebuilds, content-hashed asset references that resolve inside the bundle, a
``file://``-safe entry with no network, integrity verification that flags
missing/tampered assets, and traversal/symlink-safe archive extraction.
"""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path

import pytest

from licenselens.paths import templates_dir
from licenselens.report.bundle import (
    DATA_JS_GLOBAL,
    ICONS_JS_GLOBAL,
    REPORT_APP_VERSION,
    ReportBundleError,
    build_report_bundle,
    extract_report_archive,
    verify_report_bundle,
)
from licenselens.report.html import write_html_report
from licenselens.report.manifest import (
    ASSET_DIRNAME,
    ENTRY_FILENAME,
    MANIFEST_FILENAME,
)
from tests.report_fixtures import comprehensive_report


def _read_entry(bundle_root: Path) -> str:
    return (bundle_root / ENTRY_FILENAME).read_text(encoding="utf-8")


def _manifest(bundle_root: Path) -> dict[str, object]:
    raw = (bundle_root / ASSET_DIRNAME / MANIFEST_FILENAME).read_text(encoding="utf-8")
    return json.loads(raw)


def _build(tmp_path: Path, name: str) -> Path:
    return build_report_bundle(comprehensive_report(), tmp_path / name).root


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_two_builds_are_byte_identical(tmp_path: Path) -> None:
    first = _build(tmp_path, "first")
    second = _build(tmp_path, "second")

    assert (first / ENTRY_FILENAME).read_bytes() == (second / ENTRY_FILENAME).read_bytes()
    assert _read_entry(first) == _read_entry(second)

    first_files = sorted(p.relative_to(first).as_posix() for p in first.rglob("*") if p.is_file())
    second_files = sorted(
        p.relative_to(second).as_posix() for p in second.rglob("*") if p.is_file()
    )
    assert first_files == second_files
    for rel in first_files:
        assert (first / rel).read_bytes() == (second / rel).read_bytes(), f"diverged: {rel}"

    assert (first / "security-license-lens-report.zip").read_bytes() == (
        second / "security-license-lens-report.zip"
    ).read_bytes()


# ---------------------------------------------------------------------------
# Manifest contract
# ---------------------------------------------------------------------------


def test_manifest_lists_content_hashed_assets(tmp_path: Path) -> None:
    bundle_root = _build(tmp_path, "bundle")
    manifest = _manifest(bundle_root)
    files = manifest["files"]
    assert isinstance(files, list)
    kinds = [f["kind"] for f in files]
    assert kinds[:3] == ["style", "script", "data"]
    assert kinds.count("image") == 12
    assert set(kinds) == {"style", "script", "data", "image"}
    media = {f["media_type"] for f in files}
    assert "text/css" in media and "text/javascript" in media
    assert media <= {"text/css", "text/javascript", "image/png", "image/svg+xml"}
    for file in files:
        name = Path(str(file["path"])).name
        stem = Path(name).stem
        assert "-" in stem, f"asset name not content-hashed: {name}"


def test_entry_references_assets_that_resolve_inside_bundle(tmp_path: Path) -> None:
    bundle_root = _build(tmp_path, "bundle")
    html = _read_entry(bundle_root)
    referenced = re.findall(rf'href="({ASSET_DIRNAME}/[^"]+)"', html) + re.findall(
        rf'src="({ASSET_DIRNAME}/[^"]+)"', html
    )
    assert referenced, "entry references no assets"
    root = bundle_root.resolve()
    for rel in referenced:
        assert (bundle_root / rel).is_file(), f"entry references missing asset: {rel}"
        assert (bundle_root / rel).resolve().is_relative_to(root)


# ---------------------------------------------------------------------------
# file:// safety: no network, no inline runtime fetch
# ---------------------------------------------------------------------------


def test_entry_and_assets_are_fully_offline(tmp_path: Path) -> None:
    bundle_root = _build(tmp_path, "bundle")
    html = _read_entry(bundle_root)
    lowered = html.lower()

    # Given: the entry and asset files of a freshly built bundle.
    resources = (
        re.findall(r'<link[^>]+href="([^"]+)"', html)
        + re.findall(r'<script[^>]+src="([^"]+)"', html)
        + re.findall(r'<img[^>]+src="([^"]+)"', html)
    )

    # Then: every referenced resource is a relative asset path, never a scheme.
    assert resources, "entry references no resources"
    assert all(rel.startswith(ASSET_DIRNAME + "/") for rel in resources), resources
    assert all("://" not in rel for rel in resources), resources

    # Then: no runtime network primitive exists in the entry.
    assert "fetch(" not in lowered
    assert "@import" not in lowered
    assert "url(http" not in lowered
    assert "data:image" not in lowered

    # Then: the non-data/non-image assets (CSS/JS) are fully offline.
    manifest = _manifest(bundle_root)
    for file in manifest["files"]:
        if file["kind"] in {"data", "image"}:
            continue
        content = (bundle_root / str(file["path"])).read_text(encoding="utf-8").lower()
        assert "http://" not in content and "https://" not in content
        assert "fetch(" not in content
        assert "@import" not in content
        assert "url(http" not in content


def test_workload_icons_are_hashed_and_mapped(tmp_path: Path) -> None:
    bundle_root = _build(tmp_path, "bundle")
    manifest = _manifest(bundle_root)
    image_files = [f for f in manifest["files"] if f["kind"] == "image"]
    assert len(image_files) == 12
    for file in image_files:
        path = bundle_root / str(file["path"])
        assert path.is_file()
        assert file["sha256"] == __import__("hashlib").sha256(path.read_bytes()).hexdigest()

    data = next(bundle_root.joinpath(ASSET_DIRNAME).glob("report-data-*.js")).read_text(
        encoding="utf-8"
    )
    assert "window.LICENSELENS_WORKLOAD_ICONS" in data
    assert "identity" in data
    assert ASSET_DIRNAME in data
    assert (
        "general"
        not in data.split("LICENSELENS_WORKLOAD_ICONS", 1)[1].split("LICENSELENS_REPORT_JSON", 1)[0]
    )


def test_data_js_is_escaped_and_global_named(tmp_path: Path) -> None:
    bundle_root = _build(tmp_path, "bundle")
    data_files = list((bundle_root / ASSET_DIRNAME).glob("report-data-*.js"))
    assert len(data_files) == 1
    data = data_files[0].read_text(encoding="utf-8")
    assert data.startswith(f"{ICONS_JS_GLOBAL} = ")
    assert f"{DATA_JS_GLOBAL} = " in data
    # The malicious fixture payload must never reach the data JS raw.
    assert "<script>alert(1)</script>" not in data
    assert "</script" not in data.lower()


# ---------------------------------------------------------------------------
# Legacy compatibility
# ---------------------------------------------------------------------------


def test_legacy_entry_filename_and_html_writer_preserved(tmp_path: Path) -> None:
    bundle = build_report_bundle(comprehensive_report(), tmp_path / "bundle")
    assert bundle.entry_path.name == ENTRY_FILENAME
    assert bundle.entry_path.is_file()

    entry = tmp_path / ENTRY_FILENAME
    written = write_html_report(comprehensive_report(), entry)
    assert written == entry
    assert written.name == "security-license-lens-report.html"


def test_report_app_assets_resolve_via_paths() -> None:
    assert REPORT_APP_VERSION == "2"
    css = templates_dir() / f"report_app/v{REPORT_APP_VERSION}/app.css"
    js = templates_dir() / f"report_app/v{REPORT_APP_VERSION}/app.js"
    assert css.is_file() and css.read_bytes(), "app.css not resolvable from templates_dir()"
    assert js.is_file() and js.read_bytes(), "app.js not resolvable from templates_dir()"


# ---------------------------------------------------------------------------
# Integrity verification (missing / tampered)
# ---------------------------------------------------------------------------


def test_verify_flags_missing_asset(tmp_path: Path) -> None:
    bundle_root = _build(tmp_path, "bundle")
    assets_dir = bundle_root / ASSET_DIRNAME
    victim = next(assets_dir.glob("app-*.css"))
    victim.unlink()
    problems = verify_report_bundle(bundle_root)
    assert any("missing asset" in p for p in problems), problems


def test_verify_flags_tampered_asset(tmp_path: Path) -> None:
    bundle_root = _build(tmp_path, "bundle")
    assets_dir = bundle_root / ASSET_DIRNAME
    victim = next(assets_dir.glob("report-data-*.js"))
    victim.write_bytes(b"window.LICENSELENS_REPORT_JSON = {};\n")
    problems = verify_report_bundle(bundle_root)
    assert any("hash mismatch" in p for p in problems), problems


def test_verify_accepts_intact_bundle(tmp_path: Path) -> None:
    bundle_root = _build(tmp_path, "bundle")
    assert verify_report_bundle(bundle_root) == []


# ---------------------------------------------------------------------------
# Traversal / symlink-safe extraction
# ---------------------------------------------------------------------------


def test_extract_rejects_traversal_member(tmp_path: Path) -> None:
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(zipfile.ZipInfo("../evil.txt"), b"pwned")
    with pytest.raises(ReportBundleError):
        extract_report_archive(archive, tmp_path / "dest")
    assert not (tmp_path / "evil.txt").exists()


def test_extract_rejects_symlink_member(tmp_path: Path) -> None:
    archive = tmp_path / "link.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = 0o120777 << 16
        zf.writestr(info, b"/etc/passwd")
    with pytest.raises(ReportBundleError):
        extract_report_archive(archive, tmp_path / "dest")


def test_extract_roundtrips_a_real_bundle(tmp_path: Path) -> None:
    bundle = build_report_bundle(comprehensive_report(), tmp_path / "bundle")
    dest = extract_report_archive(bundle.archive_path, tmp_path / "extracted")
    assert (dest / ENTRY_FILENAME).is_file()
    assert verify_report_bundle(dest) == []
