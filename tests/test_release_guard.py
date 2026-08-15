"""Release automation contract tests (Todo 34).

Lock the trust invariants of the tag-gated release pipeline on any host:

  * build-once -> checksum/SBOM/attest -> promote topology with the promote job
    hard-gated on every upstream job,
  * tag-only trigger (build once from the release tag),
  * SHA-pinned actions, least-privilege permissions (``id-token`` only where OIDC
    is required),
  * version consistency (tag == pyproject version),
  * unsigned Windows artifacts cannot promote (``verify_signing.py`` gate), and
  * a dependency/license inventory cross-checked against ``THIRD_PARTY_NOTICES.md``.

Actual GitHub execution (PyPI trusted publishing, Microsoft Artifact Signing)
is deferred to the release workflow; these tests only validate the files.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from licenselens import __version__
from licenselens.release_guard import (
    REQUIRED_JOBS,
    SIGNING_STATUS_FILE,
    THIRD_PARTY_NOTICES,
    WORKFLOW_FILE,
    direct_dependencies,
    load_workflow,
    release_guards,
    signing_gate,
    third_party_notices_guards,
    version_consistent,
    version_from_pyproject,
)
from licenselens.windows_ci import action_is_pinned

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / WORKFLOW_FILE
REPO_TEXT = WORKFLOW_PATH.read_text(encoding="utf-8")

CHECKOUT_SHA = "f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a"
TRUSTED_SIGNING_SHA = "48da903ca5e2d362da62c631a42d77c02ec7eadb"


def _load() -> dict:
    return load_workflow(REPO_TEXT)


def _steps_of(job: dict) -> list[dict]:
    return [s for s in job.get("steps", []) if isinstance(s, dict)]


def _write_mutated(tmp_path: Path, old: str, new: str, *, count: int = 1) -> Path:
    assert old in REPO_TEXT, f"marker not found: {old!r}"
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    target = wf_dir / "publish.yml"
    target.write_text(REPO_TEXT.replace(old, new, count), encoding="utf-8")
    return tmp_path


def _problems(tmp_path: Path, old: str, new: str) -> list[str]:
    return release_guards(_write_mutated(tmp_path, old, new))


# ---------------------------------------------------------------------------
# Happy path: the committed workflow passes every guard
# ---------------------------------------------------------------------------


def test_committed_workflow_passes_all_guards() -> None:
    assert release_guards(REPO_ROOT) == []


def test_third_party_notices_covers_all_dependencies() -> None:
    assert third_party_notices_guards(REPO_ROOT) == []


def test_action_is_pinned_accepts_full_sha() -> None:
    assert action_is_pinned(f"actions/checkout@{CHECKOUT_SHA}")
    assert action_is_pinned(f"Azure/trusted-signing-action@{TRUSTED_SIGNING_SHA}")


def test_every_uses_action_in_workflow_is_pinned() -> None:
    data = _load()
    for job_name, job in data["jobs"].items():
        for step in job.get("steps", []):
            uses = step.get("uses")
            assert uses is None or action_is_pinned(uses), (job_name, uses)


# ---------------------------------------------------------------------------
# Topology: build once -> gates -> promote
# ---------------------------------------------------------------------------


def test_required_jobs_are_present() -> None:
    jobs = _load()["jobs"]
    for name in REQUIRED_JOBS:
        assert name in jobs, f"missing required release job: {name}"


def test_promote_needs_every_gate() -> None:
    needs = _load()["jobs"]["promote"]["needs"]
    for gate in ("build", "build-windows", "checksums", "sbom", "attest", "sign-windows"):
        assert gate in needs, f"promote must depend on '{gate}'"


def test_downstream_jobs_never_rebuild() -> None:
    # checksums/sbom/attest/promote download artifacts; only build/build-windows
    # may run `python -m build` or `pyinstaller`.
    for job_name in ("checksums", "sbom", "attest", "promote"):
        for step in _steps_of(_load()["jobs"][job_name]):
            run = step.get("run", "")
            assert "python -m build" not in run, job_name
            assert "pyinstaller" not in run, job_name


def test_checksums_assembles_after_every_promoted_surface() -> None:
    checksums = _load()["jobs"]["checksums"]
    needs = checksums["needs"]
    for upstream in ("build", "build-windows", "sbom", "sign-windows"):
        assert upstream in needs, upstream
    runs = "\n".join(step.get("run", "") for step in _steps_of(checksums))
    assert "assemble_bundle.py" in runs
    assert "SHA256SUMS" in runs
    assert "sha256sum -c" in runs


def test_attest_uses_final_assembled_bundle() -> None:
    attest = _load()["jobs"]["attest"]
    assert "checksums" in (attest.get("needs") or [])
    runs = "\n".join(step.get("run", "") for step in _steps_of(attest))
    assert "release-bundle" in runs or any(
        "release-bundle" in str(step.get("with", {})) for step in _steps_of(attest)
    )


def test_promote_validates_trust_receipts_and_attestation() -> None:
    runs = "\n".join(step.get("run", "") for step in _steps_of(_load()["jobs"]["promote"]))
    assert "verify_attestation.py" in runs
    assert "validate_receipts.py" in runs
    assert "verify_signing.py" in runs
    assert "SHA256SUMS" in runs or "sha256sum" in runs


# ---------------------------------------------------------------------------
# Triggers, permissions, version consistency
# ---------------------------------------------------------------------------


def test_workflow_is_tag_gated_only() -> None:
    on = _load()["on"]
    assert on["push"]["tags"] == ["v*"]
    assert "pull_request" not in on
    assert "branches" not in on["push"]


def test_top_level_permissions_are_minimal() -> None:
    assert _load()["permissions"] == {"contents": "read"}


def test_id_token_is_job_scoped_not_top_level() -> None:
    data = _load()
    assert data["permissions"].get("id-token") != "write"
    for job_name in ("attest", "sign-windows", "promote"):
        assert data["jobs"][job_name]["permissions"]["id-token"] == "write", job_name


def test_version_consistency() -> None:
    assert version_consistent(REPO_ROOT, f"v{__version__}")
    assert not version_consistent(REPO_ROOT, "v9.9.9")
    assert not version_consistent(REPO_ROOT, "not-a-tag")
    assert version_from_pyproject(REPO_ROOT) == __version__


def test_build_job_runs_version_and_license_guards() -> None:
    runs = [step.get("run", "") for step in _steps_of(_load()["jobs"]["build"])]
    joined = "\n".join(runs)
    assert "verify_version.py" in joined
    assert "license_inventory.py" in joined


def test_promote_runs_signing_gate_before_publish() -> None:
    steps = _steps_of(_load()["jobs"]["promote"])
    signing_idx = next(i for i, s in enumerate(steps) if "verify_signing.py" in s.get("run", ""))
    pypi_idx = next(i for i, s in enumerate(steps) if "pypi-publish" in s.get("uses", ""))
    assert signing_idx < pypi_idx, "signing gate must run before PyPI publish"


def test_sign_windows_step_is_config_gated() -> None:
    sign = _load()["jobs"]["sign-windows"]
    signing_steps = [s for s in _steps_of(sign) if "trusted-signing-action" in s.get("uses", "")]
    assert signing_steps, "expected a trusted-signing-action step"
    for step in signing_steps:
        assert step.get("if"), "trusted-signing step must be gated by config"


# ---------------------------------------------------------------------------
# Signing gate (pure helper)
# ---------------------------------------------------------------------------


def _signed_assets(tmp_path: Path) -> Path:
    (tmp_path / "licenselens-windows-x64-0.3.0.zip").write_bytes(b"zip")
    (tmp_path / SIGNING_STATUS_FILE).write_text('{"signed": true}', encoding="utf-8")
    return tmp_path


def _unsigned_assets(tmp_path: Path) -> Path:
    (tmp_path / "licenselens-windows-x64-0.3.0-test-only.zip").write_bytes(b"zip")
    (tmp_path / SIGNING_STATUS_FILE).write_text('{"signed": false}', encoding="utf-8")
    return tmp_path


def test_signing_gate_required_rejects_unsigned(tmp_path: Path) -> None:
    ok, msg = signing_gate("required", _unsigned_assets(tmp_path))
    assert not ok
    assert "required" in msg


def test_signing_gate_required_accepts_signed(tmp_path: Path) -> None:
    ok, _ = signing_gate("required", _signed_assets(tmp_path))
    assert ok


def test_signing_gate_rejects_misleading_signed_marker(tmp_path: Path) -> None:
    (tmp_path / "licenselens-windows-x64-0.3.0-test-only.zip").write_bytes(b"zip")
    (tmp_path / SIGNING_STATUS_FILE).write_text('{"signed": true}', encoding="utf-8")
    ok, _ = signing_gate("required", tmp_path)
    assert not ok


def test_signing_gate_optional_allows_unsigned(tmp_path: Path) -> None:
    ok, msg = signing_gate("optional", _unsigned_assets(tmp_path))
    assert ok
    assert "test-only" in msg


def test_signing_gate_off_allows_unsigned(tmp_path: Path) -> None:
    assert signing_gate("off", _unsigned_assets(tmp_path))[0]


def test_signing_gate_unknown_policy_fails(tmp_path: Path) -> None:
    ok, _ = signing_gate("bogus", tmp_path)
    assert not ok


# ---------------------------------------------------------------------------
# Script CLI round-trips (run the actual scripts, not just the helpers)
# ---------------------------------------------------------------------------


def _run_script(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "release" / script), *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_verify_version_script_passes_on_match() -> None:
    result = _run_script("verify_version.py", f"v{__version__}")
    assert result.returncode == 0, result.stderr


def test_verify_version_script_fails_on_mismatch() -> None:
    result = _run_script("verify_version.py", "v9.9.9")
    assert result.returncode == 1
    assert "mismatch" in result.stderr


def test_verify_signing_script_rejects_unsigned(tmp_path: Path) -> None:
    _unsigned_assets(tmp_path)
    result = _run_script("verify_signing.py", "--policy", "required", "--assets", str(tmp_path))
    assert result.returncode == 2, result.stdout


def test_verify_signing_script_accepts_signed(tmp_path: Path) -> None:
    _signed_assets(tmp_path)
    result = _run_script("verify_signing.py", "--policy", "required", "--assets", str(tmp_path))
    assert result.returncode == 0, result.stderr


# ---------------------------------------------------------------------------
# Dependency inventory
# ---------------------------------------------------------------------------


def test_direct_dependencies_match_pyproject() -> None:
    names = [name for name, _ in direct_dependencies(REPO_ROOT / "pyproject.toml")]
    assert "azure-identity" in names
    assert "typer" in names
    assert len(names) == 8


def test_notices_guard_flags_missing_dependency(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nversion = "0.3.0"\ndependencies = ["hypothetical-dep>=1"]\n',
        encoding="utf-8",
    )
    (tmp_path / THIRD_PARTY_NOTICES).write_text("azure-identity MIT", encoding="utf-8")
    problems = third_party_notices_guards(tmp_path)
    assert any("hypothetical-dep" in p for p in problems)


# ---------------------------------------------------------------------------
# Negative detection via a mutated copy of the committed workflow
# ---------------------------------------------------------------------------


def test_guard_flags_unpinned_action(tmp_path: Path) -> None:
    problems = _problems(tmp_path, f"actions/checkout@{CHECKOUT_SHA}", "actions/checkout@v4")
    assert any("unpinned" in p for p in problems)


def test_guard_flags_branch_trigger(tmp_path: Path) -> None:
    problems = _problems(
        tmp_path,
        'on:\n  push:\n    tags:\n      - "v*"',
        'on:\n  push:\n    branches: [main]\n    tags:\n      - "v*"',
    )
    assert any("branch" in p for p in problems)


def test_guard_flags_top_level_id_token_write(tmp_path: Path) -> None:
    problems = _problems(tmp_path, "contents: read", "contents: read\n  id-token: write")
    assert any("id-token" in p for p in problems)


def test_guard_flags_missing_version_guard(tmp_path: Path) -> None:
    problems = _problems(
        tmp_path,
        "python scripts/release/verify_version.py",
        "python scripts/release/verify_old_version.py",
    )
    assert any("version-consistency" in p for p in problems)


def test_guard_flags_missing_signing_gate(tmp_path: Path) -> None:
    problems = _problems(
        tmp_path,
        "python scripts/release/verify_signing.py",
        "python scripts/release/skip_signing.py",
    )
    assert any("unsigned-can't-promote" in p for p in problems)


def test_guard_flags_promote_without_tag_gate(tmp_path: Path) -> None:
    problems = _problems(
        tmp_path,
        "if: startsWith(github.ref, 'refs/tags/v')",
        "if: github.ref == 'refs/heads/main'",
    )
    assert any("tag-gated" in p for p in problems)


def test_guard_flags_promote_missing_sign_needs(tmp_path: Path) -> None:
    problems = _problems(
        tmp_path,
        "needs: [build, build-windows, checksums, sbom, attest, sign-windows]",
        "needs: [build, build-windows, checksums, sbom, attest]",
    )
    assert any("'sign-windows'" in p for p in problems)


def test_guard_flags_malformed_yaml(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "publish.yml").write_text("jobs: [unclosed\n", encoding="utf-8")
    assert any("does not parse" in p for p in release_guards(tmp_path))
