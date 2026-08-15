"""Windows per-user installer contract (Todo 32).

Cross-platform static guards for the PowerShell install/update/uninstall
scripts. The scripts themselves run on Windows; this module lets the CI
(locally and on any host) verify the *trust contract* without pwsh:

  * a release manifest schema (SHA-256 per artifact + a signed flag),
  * checksum verification before extraction,
  * Authenticode enforced only when a signature is promised,
  * an atomic ``current`` shim switch,
  * user PATH changed only with explicit consent,
  * uninstall removes only owned paths, and
  * the scripts never recommend ``irm <url> | iex``.

No PowerShell dependency; everything here is plain Python.
"""

from __future__ import annotations

import re
from pathlib import Path

RELEASE_MANIFEST_SCHEMA_VERSION: int = 1
INSTALL_SUBDIR: str = "LicenseLens"
APP_NAME: str = "licenselens"

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$")

#: Files that must never recommend piping a remote payload into Invoke-Expression.
#: The literal ``irm <url> | iex`` may appear only inside a "do NOT run" warning.
INSTALLER_SCRIPT_FILES: tuple[str, ...] = (
    "packaging/windows/Install-LicenseLens.ps1",
    "packaging/windows/Update-LicenseLens.ps1",
    "packaging/windows/Uninstall-LicenseLens.ps1",
    "packaging/windows/LicenseLens.Installer.psm1",
)


def validate_release_manifest(manifest: dict) -> list[str]:
    """Validate a release manifest; return a list of problems (empty == valid)."""
    problems: list[str] = []
    if not isinstance(manifest, dict):
        return ["release manifest must be a JSON object"]
    if manifest.get("schema_version") != RELEASE_MANIFEST_SCHEMA_VERSION:
        problems.append(f"schema_version must be {RELEASE_MANIFEST_SCHEMA_VERSION}")
    version = manifest.get("version")
    if not isinstance(version, str) or not VERSION_RE.match(version):
        problems.append("manifest 'version' is missing or not a semver string")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        problems.append("manifest 'artifacts' must be a non-empty object")
    else:
        for name, entry in artifacts.items():
            if not isinstance(entry, dict):
                problems.append(f"artifact '{name}' must be an object")
                continue
            sha = entry.get("sha256")
            if not isinstance(sha, str) or not SHA256_RE.match(sha):
                problems.append(f"artifact '{name}' has an invalid sha256")
            if not isinstance(entry.get("signed"), bool):
                problems.append(f"artifact '{name}' 'signed' must be a boolean")
    return problems


def compute_sha256(path: Path) -> str:
    """Return the lowercase hex SHA-256 of a file."""
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _script_text(script_path: Path) -> str:
    return script_path.read_text(encoding="utf-8")


def no_irm_iex_recommendation(text: str) -> list[str]:
    """Return lines that recommend download-and-execute (``irm <url> | iex``).

    A line is flagged only when it *begins* with a download cmdlet and also
    mentions ``iex`` / ``Invoke-Expression`` — i.e. an actual command, not a
    warning. The scripts may reference the anti-pattern in prose ("Do not run
    `irm https://... | iex`") without being flagged.
    """
    problems: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^(irm|iwr|invoke-webrequest|invoke-restmethod)\b", stripped, re.IGNORECASE):
            if re.search(r"\biex\b|invoke-expression", stripped, re.IGNORECASE):
                problems.append(stripped)
    return problems


def script_contract_guards(repo_root: Path) -> list[str]:
    """Static guards over the committed installer scripts; empty == all pass."""
    problems: list[str] = []
    module = repo_root / "packaging" / "windows" / "LicenseLens.Installer.psm1"
    install = repo_root / "packaging" / "windows" / "Install-LicenseLens.ps1"
    update = repo_root / "packaging" / "windows" / "Update-LicenseLens.ps1"
    uninstall = repo_root / "packaging" / "windows" / "Uninstall-LicenseLens.ps1"

    for name, path in (
        ("module", module),
        ("install", install),
        ("update", update),
        ("uninstall", uninstall),
    ):
        if not path.is_file():
            problems.append(f"missing file: {path.name}")
            continue
        text = _script_text(path)
        for offender in no_irm_iex_recommendation(text):
            problems.append(f"{name}: recommends irm|iex: {offender}")

    if module.is_file():
        mod = _script_text(module)
        if "Get-FileHash" not in mod and "Test-LicenseLensArchiveChecksum" not in mod:
            problems.append("module: no SHA-256 checksum verification")
        if "Get-AuthenticodeSignature" not in mod:
            problems.append("module: no Authenticode check")
        if "[System.IO.File]::Replace" not in mod:
            problems.append("module: no atomic file switch")
        if "Test-LicenseLensOwnedPath" not in mod or "owned_paths" not in mod:
            problems.append("module: no owned-paths removal guard")
        if "Get-LicenseLensPreviousVersion" not in mod:
            problems.append("module: no previous-version rollback support")

    if install.is_file():
        inst = _script_text(install)
        if "Install-LicenseLens" not in inst:
            problems.append("install: missing Install-LicenseLens entry point")
        if "AddToPath" not in inst:
            problems.append("install: no -AddToPath consent switch")
    if uninstall.is_file():
        un = _script_text(uninstall)
        if "Uninstall-LicenseLens" not in un:
            problems.append("uninstall: missing Uninstall-LicenseLens entry point")
    if update.is_file():
        upd = _script_text(update)
        if "Rollback" not in upd:
            problems.append("update: no -Rollback support")

    return problems
