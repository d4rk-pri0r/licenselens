"""Wheel-content contract tests (Todo 24 / B2).

``pip install``/``pipx install`` users run from the wheel, so the wheel must
carry the read-only PowerShell collector bridge — without it the email (EXO),
collaboration, and power-data packs cannot run on Windows, even though the
PyInstaller exe bundles it. Lock the force-include mapping to the destination
layout the frozen one-folder exe uses (``windows_dist.DATA_DIRS``) and, when a
build toolchain is present, build a real wheel and assert the bridge files
land inside it while the module's Pester tests do not.
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest

from licenselens.windows_dist import DATA_DIRS

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"

BRIDGE_SOURCE = "powershell/LicenseLens.Collectors"
BRIDGE_DEST = "licenselens/data/powershell/LicenseLens.Collectors"

# Runtime bridge members the CLI shells out to (see collectors/powershell.py).
BRIDGE_MEMBERS = (
    "LicenseLens.Collectors.psd1",
    "LicenseLens.Collectors.psm1",
    "Invoke-LicenseLensBridge.ps1",
    "adapters/exo_threat_policies.ps1",
)


def _force_include() -> dict[str, str]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return dict(data["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"])


def test_force_include_ships_bridge_into_package_data() -> None:
    entries = {
        source: dest
        for source, dest in _force_include().items()
        if source.startswith(BRIDGE_SOURCE)
    }
    assert entries, "wheel force-include carries no PowerShell bridge sources"
    for source, dest in entries.items():
        assert dest == source.replace(BRIDGE_SOURCE, BRIDGE_DEST, 1)
        assert (REPO_ROOT / source).exists()
    for member in BRIDGE_MEMBERS:
        source = f"{BRIDGE_SOURCE}/{member}"
        assert (REPO_ROOT / source).is_file()
        covered = any(source == entry or source.startswith(f"{entry}/") for entry in entries)
        assert covered, f"{source} is not covered by a force-include entry"
    assert not any("/tests/" in source for source in entries)


def test_bridge_dest_agrees_with_frozen_exe_layout() -> None:
    frozen_sources = {dest: source for source, dest in DATA_DIRS}
    assert frozen_sources.get(BRIDGE_DEST) == BRIDGE_SOURCE


def test_built_wheel_contains_bridge_and_omits_module_tests(tmp_path: Path) -> None:
    try:
        import hatchling  # noqa: F401
    except ImportError:
        pip = subprocess.run(
            [sys.executable, "-m", "pip", "--version"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if pip.returncode != 0:
            pytest.skip("wheel build needs hatchling or pip (isolated build)")
        argv = [sys.executable, "-m", "build", "--wheel", "--outdir", str(tmp_path)]
    else:
        argv = [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(tmp_path),
        ]
    result = subprocess.run(
        argv, cwd=REPO_ROOT, capture_output=True, text=True, timeout=600, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
    wheels = sorted(tmp_path.glob("*.whl"))
    assert len(wheels) == 1, f"expected one wheel, got {wheels}"
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
    for member in BRIDGE_MEMBERS:
        assert f"{BRIDGE_DEST}/{member}" in names
    assert not any("/tests/" in name for name in names)
    assert not any(name.startswith("powershell/") for name in names)
