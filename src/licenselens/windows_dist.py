"""Windows x64 one-folder distribution contract (PyInstaller packaging).

This module is importable cross-platform (it has no PyInstaller import) so the
data-collection list, the one-folder guard, and the deterministic ZIP helper can
be tested on any host. The actual Windows executable is built on a Windows
runner via ``packaging/windows/licenselens.spec``; PyInstaller is not a
cross-compiler, so a Windows artifact can never be produced from macOS/Linux.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Final

APP_NAME: Final = "licenselens"
SPEC_FILENAME: Final = "licenselens.spec"
VERSION_FILE: Final = "version_info.txt"
ICON_FILE: Final = "licenselens.ico"

SUPPORTED_ARCH: Final = ("x64",)
SUPPORTED_PYTHON: Final = ("3.12", "3.13")

ZIP_TIMESTAMP: Final = (1980, 1, 1, 0, 0, 0)

#: Source directory (relative to repo root) -> frozen destination under the
#: ``licenselens`` package tree. Destinations must match ``licenselens.paths``
#: (catalog/checks/templates) and ``powershell_module_root`` (powershell).
DATA_DIRS: Final = (
    ("catalog", "licenselens/data/catalog"),
    ("checks", "licenselens/data/checks"),
    ("templates", "licenselens/data/templates"),
    (
        "assets/vendor/microsoft-cloud",
        "licenselens/data/vendor/microsoft-cloud",
    ),
    (
        "powershell/LicenseLens.Collectors",
        "licenselens/data/powershell/LicenseLens.Collectors",
    ),
)


class WindowsDistError(Exception):
    """Raised when the Windows distribution contract is violated."""


def assert_one_folder(spec_source: str) -> None:
    """Reject a one-file spec; LicenseLens ships only as a one-folder build."""
    if "COLLECT(" not in spec_source:
        raise WindowsDistError(
            "one-file mode is unsupported: the spec must emit a one-folder "
            "COLLECT() build (no temp-extraction executable)"
        )
    if "exclude_binaries=True" not in spec_source:
        raise WindowsDistError(
            "one-folder build requires EXE(exclude_binaries=True); a one-file "
            "spec embeds a.binaries/a.datas inside the executable"
        )


def collect_data_files(repo_root: Path) -> list[tuple[str, str]]:
    """Return PyInstaller ``datas`` entries for every runtime data directory."""
    entries: list[tuple[str, str]] = []
    for source, dest in DATA_DIRS:
        source_path = repo_root / source
        if not source_path.is_dir():
            raise WindowsDistError(f"data directory not found: {source}")
        entries.append((str(source_path), dest))
    return entries


def verify_data_collection(repo_root: Path) -> list[str]:
    """Return missing/empty data problems; an empty list means the data is intact."""
    problems: list[str] = []
    for source, _dest in DATA_DIRS:
        source_path = repo_root / source
        if not source_path.is_dir():
            problems.append(f"missing data directory: {source}")
        elif not any(source_path.rglob("*")):
            problems.append(f"empty data directory: {source}")
    return problems


def distribution_archive_name(version: str, *, signed: bool) -> str:
    """Name the distribution ZIP; unsigned artifacts are labeled test-only."""
    label = "" if signed else "-test-only"
    return f"{APP_NAME}-windows-x64-{version}{label}.zip"


def write_deterministic_zip(source_dir: Path, archive_path: Path) -> Path:
    """ZIP a one-folder directory deterministically (fixed times, sorted, stored)."""
    root = source_dir.resolve()
    if not root.is_dir():
        raise WindowsDistError(f"distribution directory not found: {source_dir}")
    archive_target = archive_path.resolve()
    members = sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix())
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
        for member in members:
            if member.resolve() == archive_target:
                continue
            relative = member.relative_to(root).as_posix()
            info = zipfile.ZipInfo(relative, ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            if member.is_dir():
                info.external_attr = 0o040755 << 16
                archive.writestr(info, b"")
            elif member.is_file() and not member.is_symlink():
                info.external_attr = 0o100644 << 16
                archive.writestr(info, member.read_bytes())
    return archive_path
