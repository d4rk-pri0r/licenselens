"""Windows per-user installer contract tests (Todo 32).

Lock the cross-platform static guards for the PowerShell install/update/uninstall
scripts: the release manifest schema, checksum/Authenticode/atomic-switch/PATH-
consent/owned-removal guarantees, and the hard rule that no script recommends
`irm <url> | iex`. The behavioral lifecycle is covered by Pester
(packaging/windows/tests/Installer.Tests.ps1); these tests run everywhere.
"""

from __future__ import annotations

from pathlib import Path

from licenselens.windows_installer import (
    APP_NAME,
    INSTALL_SUBDIR,
    INSTALLER_SCRIPT_FILES,
    RELEASE_MANIFEST_SCHEMA_VERSION,
    compute_sha256,
    no_irm_iex_recommendation,
    script_contract_guards,
    validate_release_manifest,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _valid_manifest() -> dict:
    return {
        "schema_version": 1,
        "product": APP_NAME,
        "version": "0.3.0",
        "artifacts": {
            "licenselens-windows-x64-0.3.0.zip": {
                "sha256": "a" * 64,
                "signed": True,
            },
            "licenselens-windows-x64-0.3.0-test-only.zip": {
                "sha256": "b" * 64,
                "signed": False,
            },
        },
    }


# ---------------------------------------------------------------------------
# Release manifest schema
# ---------------------------------------------------------------------------


def test_valid_release_manifest_has_no_problems() -> None:
    assert validate_release_manifest(_valid_manifest()) == []


def test_manifest_rejects_wrong_schema_version() -> None:
    manifest = _valid_manifest()
    manifest["schema_version"] = 999
    assert any("schema_version" in p for p in validate_release_manifest(manifest))


def test_manifest_rejects_missing_version() -> None:
    manifest = _valid_manifest()
    del manifest["version"]
    assert any("version" in p for p in validate_release_manifest(manifest))


def test_manifest_rejects_bad_sha256() -> None:
    manifest = _valid_manifest()
    manifest["artifacts"]["licenselens-windows-x64-0.3.0.zip"]["sha256"] = "not-hex"
    assert any("sha256" in p for p in validate_release_manifest(manifest))


def test_manifest_rejects_non_bool_signed() -> None:
    manifest = _valid_manifest()
    manifest["artifacts"]["licenselens-windows-x64-0.3.0.zip"]["signed"] = "yes"
    assert any("signed" in p for p in validate_release_manifest(manifest))


def test_manifest_rejects_empty_artifacts() -> None:
    manifest = _valid_manifest()
    manifest["artifacts"] = {}
    assert any("artifacts" in p for p in validate_release_manifest(manifest))


# ---------------------------------------------------------------------------
# Static script guards
# ---------------------------------------------------------------------------


def test_all_installer_scripts_exist() -> None:
    for rel in INSTALLER_SCRIPT_FILES:
        assert (REPO_ROOT / rel).is_file(), rel


def test_committed_scripts_pass_static_guards() -> None:
    assert script_contract_guards(REPO_ROOT) == []


def test_no_irm_iex_recommendation_allows_only_warnings() -> None:
    for rel in INSTALLER_SCRIPT_FILES:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        # The literal pattern may appear only inside a "do not run" warning.
        assert no_irm_iex_recommendation(text) == [], rel


def test_no_irm_iex_recommendation_flags_bare_pipe() -> None:
    assert no_irm_iex_recommendation("irm https://x/install | iex") != []


def test_module_has_atomic_switch_and_rollback() -> None:
    module = (REPO_ROOT / "packaging" / "windows" / "LicenseLens.Installer.psm1").read_text(
        encoding="utf-8"
    )
    assert "[System.IO.File]::Replace" in module
    assert "Get-LicenseLensPreviousVersion" in module


def test_module_guards_owned_path_removal() -> None:
    module = (REPO_ROOT / "packaging" / "windows" / "LicenseLens.Installer.psm1").read_text(
        encoding="utf-8"
    )
    assert "Test-LicenseLensOwnedPath" in module
    assert "owned_paths" in module


# ---------------------------------------------------------------------------
# Shared constants and helpers
# ---------------------------------------------------------------------------


def test_install_subdir_matches_layout() -> None:
    assert INSTALL_SUBDIR == "LicenseLens"
    assert RELEASE_MANIFEST_SCHEMA_VERSION == 1


def test_compute_sha256_is_deterministic(tmp_path: Path) -> None:
    f = tmp_path / "payload.bin"
    f.write_bytes(b"license lens fixture")
    assert compute_sha256(f) == compute_sha256(f)
    assert len(compute_sha256(f)) == 64
