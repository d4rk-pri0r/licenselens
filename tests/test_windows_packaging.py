"""Windows one-folder distribution contract tests (Todo 31).

Lock the cross-platform pieces of the Windows x64 PyInstaller build: the data
collection list matches ``licenselens.paths``/``powershell_module_root``, the
spec is structurally one-folder and rejects one-file mode, the archive name
labels unsigned builds test-only, and the deterministic ZIP is byte-stable.
The exe itself can only be built on Windows (PyInstaller is not a
cross-compiler), so the frozen artifact is deferred to Windows CI here.
"""

from __future__ import annotations

import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from licenselens import __version__
from licenselens.windows_dist import (
    SPEC_FILENAME,
    SUPPORTED_ARCH,
    SUPPORTED_PYTHON,
    WindowsDistError,
    assert_one_folder,
    collect_data_files,
    distribution_archive_name,
    verify_data_collection,
    write_deterministic_zip,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = REPO_ROOT / "packaging" / "windows" / SPEC_FILENAME
VERSION_FILE = REPO_ROOT / "packaging" / "windows" / "version_info.txt"

ONEFILE_SPEC = """\
a = Analysis(["app.py"])
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="app", console=True)
"""


def _run_module(*args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "licenselens", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )


# ---------------------------------------------------------------------------
# Data collection contract
# ---------------------------------------------------------------------------


def test_data_collection_is_intact_and_maps_to_frozen_layout() -> None:
    assert verify_data_collection(REPO_ROOT) == []
    entries = collect_data_files(REPO_ROOT)
    assert len(entries) == 5
    for source, dest in entries:
        assert Path(source).is_dir()
        assert dest.startswith("licenselens/data/")
    dests = {dest for _, dest in entries}
    assert "licenselens/data/catalog" in dests
    assert "licenselens/data/checks" in dests
    assert "licenselens/data/templates" in dests
    assert "licenselens/data/vendor/microsoft-cloud" in dests
    assert "licenselens/data/powershell/LicenseLens.Collectors" in dests


def test_templates_tree_ships_only_v2_report_partials() -> None:
    # Dead v1 report partials (report/_*.j2) were deleted; a future re-creation
    # would be shipped whole by collect_data_files, so fail loudly if one returns.
    templates = REPO_ROOT / "templates"
    stale_v1 = sorted((templates / "report").glob("_*.j2"))
    assert stale_v1 == []
    assert (templates / "report.html.j2").is_file()
    assert (templates / "report" / "v2").is_dir()
    assert (templates / "report_app").is_dir()


def test_missing_data_directory_is_flagged(tmp_path: Path) -> None:
    (tmp_path / "checks").mkdir()
    (tmp_path / "templates").mkdir()
    (tmp_path / "assets/vendor/microsoft-cloud").mkdir(parents=True)
    (tmp_path / "powershell").mkdir()
    problems = verify_data_collection(tmp_path)
    assert any("missing data directory: catalog" == p for p in problems)
    with pytest.raises(WindowsDistError, match="catalog"):
        collect_data_files(tmp_path)


# ---------------------------------------------------------------------------
# One-folder guard
# ---------------------------------------------------------------------------


def test_one_folder_guard_rejects_onefile_spec() -> None:
    with pytest.raises(WindowsDistError, match="one-file mode is unsupported"):
        assert_one_folder(ONEFILE_SPEC)


def test_committed_spec_is_one_folder() -> None:
    assert_one_folder(SPEC_PATH.read_text(encoding="utf-8"))


def test_committed_spec_collects_data_and_builds_one_folder() -> None:
    source = SPEC_PATH.read_text(encoding="utf-8")
    assert "collect_data_files" in source
    assert "exclude_binaries=True" in source
    assert "COLLECT(" in source
    assert "one-file" in source and "unsupported" in source


# ---------------------------------------------------------------------------
# Archive naming: unsigned builds are labeled test-only
# ---------------------------------------------------------------------------


def test_unsigned_archive_is_labeled_test_only() -> None:
    assert distribution_archive_name("0.3.0", signed=False).endswith("-test-only.zip")


def test_signed_archive_omits_test_only_label() -> None:
    name = distribution_archive_name("0.3.0", signed=True)
    assert "-test-only" not in name
    assert name == "licenselens-windows-x64-0.3.0.zip"


def test_archive_name_carries_arch_and_version() -> None:
    name = distribution_archive_name(__version__, signed=False)
    assert "windows-x64" in name
    assert __version__ in name


# ---------------------------------------------------------------------------
# Deterministic ZIP
# ---------------------------------------------------------------------------


def _build_fake_folder(root: Path) -> Path:
    (root / "_internal" / "data" / "catalog").mkdir(parents=True)
    (root / "_internal" / "data" / "catalog" / "capabilities.yaml").write_text("x")
    (root / "_internal" / "licenselens.exe").write_bytes(b"MZfake")
    (root / "README.txt").write_text("hello")
    return root


def test_zip_is_deterministic(tmp_path: Path) -> None:
    folder = _build_fake_folder(tmp_path / "dist" / "licenselens")
    first = write_deterministic_zip(folder, tmp_path / "first.zip")
    second = write_deterministic_zip(folder, tmp_path / "second.zip")
    assert first.read_bytes() == second.read_bytes()


def test_zip_uses_fixed_timestamps(tmp_path: Path) -> None:
    folder = _build_fake_folder(tmp_path / "dist" / "licenselens")
    archive = write_deterministic_zip(folder, tmp_path / "out.zip")
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        assert infos, "zip has no members"
        for info in infos:
            assert info.date_time == (1980, 1, 1, 0, 0, 0), info.filename
            assert info.compress_type == zipfile.ZIP_STORED


def test_zip_rejects_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(WindowsDistError, match="not found"):
        write_deterministic_zip(tmp_path / "nope", tmp_path / "out.zip")


# ---------------------------------------------------------------------------
# Metadata and support matrix
# ---------------------------------------------------------------------------


def test_support_matrix_is_explicit() -> None:
    assert SUPPORTED_ARCH == ("x64",)
    assert "3.12" in SUPPORTED_PYTHON and "3.13" in SUPPORTED_PYTHON


def test_version_file_matches_package_version() -> None:
    text = VERSION_FILE.read_text(encoding="utf-8")
    assert __version__ in text
    assert "Security License Lens" in text
    assert "licenselens.exe" in text


# ---------------------------------------------------------------------------
# __main__ smoke: `python -m licenselens` routes through the CLI entrypoint
# ---------------------------------------------------------------------------


def test_main_module_version_smoke() -> None:
    result = _run_module("version")
    assert result.returncode == 0, result.stderr
    assert "Security License Lens" in result.stdout
    assert __version__ in result.stdout


def test_main_module_checks_smoke() -> None:
    result = _run_module("checks")
    assert result.returncode == 0, result.stderr
    assert "Workload" in result.stdout
    assert "Backend" in result.stdout
    assert "enabled" in result.stdout
