# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller one-folder spec for the Windows x64 LicenseLens distribution.

Build on a supported Windows host only (PyInstaller is not a cross-compiler):

    pyinstaller --clean --noconfirm packaging/windows/licenselens.spec

Outputs ``dist/licenselens/`` (one-folder) plus a deterministic ZIP. The exe is
unsigned; downstream CI must label the artifact ``test-only`` (see
``distribution_archive_name``) and never promote it to a production channel.
"""

import sys
from pathlib import Path

spec_dir = Path(SPECPATH)  # PyInstaller-provided spec directory
repo_root = spec_dir.parent.parent

sys.path.insert(0, str(repo_root / "src"))
sys.path.insert(0, str(spec_dir))

from licenselens import __version__  # noqa: E402
from licenselens.windows_dist import (  # noqa: E402
    APP_NAME,
    ICON_FILE,
    SPEC_FILENAME,
    VERSION_FILE,
    assert_one_folder,
    collect_data_files,
    distribution_archive_name,
    write_deterministic_zip,
)

# One-folder contract: one-file mode is unsupported; reject any drift at build time.
assert_one_folder((spec_dir / SPEC_FILENAME).read_text(encoding="utf-8"))

entry_script = repo_root / "src" / "licenselens" / "__main__.py"
datas = collect_data_files(repo_root)

a = Analysis(
    [str(entry_script)],
    pathex=[str(repo_root / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

icon = spec_dir / ICON_FILE
exe_kwargs = dict(
    name=APP_NAME,
    console=True,
    version=str(spec_dir / VERSION_FILE),
    exclude_binaries=True,  # one-folder: keep binaries out of the exe
)
if icon.is_file():
    exe_kwargs["icon"] = str(icon)
exe = EXE(pyz, a.scripts, [], **exe_kwargs)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name=APP_NAME,
)

# Deterministic ZIP of the one-folder directory (fixed timestamps, sorted order).
# The build-time exe is unsigned, so the archive is labeled test-only; the
# release job (signing configured) re-packages with distribution_archive_name(signed=True).
write_deterministic_zip(
    Path(DISTPATH) / APP_NAME,
    Path(DISTPATH) / distribution_archive_name(__version__, signed=False),
)
