"""Windows CI workflow contract tests (Todo 33).

Lock the trust invariants of ``.github/workflows/windows-ci.yml`` on any host:
every action is pinned by full commit SHA, the workflow runs least-privileged
(``contents: read``, no ``id-token``), fork PRs cannot reach any secret, every
job has a timeout, the Python matrix covers 3.12/3.13, and uploaded test
artifacts are explicitly unsigned and expiring. The actual Windows execution is
deferred to GitHub-hosted runners; these tests only validate the workflow file.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from licenselens.windows_ci import (
    REQUIRED_JOBS,
    SUPPORTED_PYTHON,
    WORKFLOW_FILE,
    action_is_pinned,
    windows_ci_guards,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / WORKFLOW_FILE
REPO_TEXT = WORKFLOW_PATH.read_text(encoding="utf-8")

CHECKOUT_SHA = "f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a"


def _load() -> dict:
    return yaml.safe_load(REPO_TEXT)


def _write_mutated(tmp_path: Path, old: str, new: str) -> Path:
    assert old in REPO_TEXT, f"marker not found: {old!r}"
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    target = wf_dir / "windows-ci.yml"
    target.write_text(REPO_TEXT.replace(old, new, 1), encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# Action pinning (SHA-only)
# ---------------------------------------------------------------------------


def test_committed_workflow_passes_all_guards() -> None:
    assert windows_ci_guards(REPO_ROOT) == []


def test_action_is_pinned_accepts_full_sha() -> None:
    assert action_is_pinned(f"actions/checkout@{CHECKOUT_SHA}")


@pytest.mark.parametrize(
    "uses",
    [
        "actions/checkout@v4",
        "actions/checkout@main",
        "actions/checkout@release/v1",
        "actions/checkout",
        "actions/checkout@f548e57",  # truncated SHA
    ],
)
def test_action_is_pinned_rejects_floating_or_short_refs(uses: str) -> None:
    assert action_is_pinned(uses) is False


def test_every_uses_action_in_workflow_is_pinned() -> None:
    data = _load()
    for job_name, job in data["jobs"].items():
        for step in job.get("steps", []):
            uses = step.get("uses")
            assert uses is None or action_is_pinned(uses), (job_name, uses)


# ---------------------------------------------------------------------------
# Required jobs and matrix
# ---------------------------------------------------------------------------


def test_required_jobs_are_present() -> None:
    jobs = _load()["jobs"]
    for name in REQUIRED_JOBS:
        assert name in jobs, f"missing required Windows job: {name}"


def test_python_matrix_covers_supported_versions() -> None:
    matrix = _load()["jobs"]["python"]["strategy"]["matrix"]["python-version"]
    for version in SUPPORTED_PYTHON:
        assert version in matrix


def test_every_job_runs_on_windows_and_has_a_timeout() -> None:
    for name, job in _load()["jobs"].items():
        assert job["runs-on"] == "windows-latest", name
        assert job.get("timeout-minutes"), f"{name} is missing a timeout"


# ---------------------------------------------------------------------------
# Least privilege, concurrency, fork-PR secret protection
# ---------------------------------------------------------------------------


def test_workflow_is_least_privilege() -> None:
    perms = _load()["permissions"]
    assert perms == {"contents": "read"}


def test_workflow_has_cancel_in_progress_concurrency() -> None:
    concurrency = _load()["concurrency"]
    assert "group" in concurrency
    assert concurrency["cancel-in-progress"] is True


def test_no_secret_reference_anywhere() -> None:
    # A test workflow must reference no secret expression, so a fork PR can
    # never reach signing or download credentials.
    assert "${{ secrets." not in REPO_TEXT


def test_uploaded_artifacts_are_unsigned_and_expiring() -> None:
    jobs = _load()["jobs"]
    uploads = [
        step
        for job in jobs.values()
        for step in job.get("steps", [])
        if step.get("uses", "").startswith("actions/upload-artifact")
    ]
    assert uploads, "expected at least one upload-artifact step"
    for step in uploads:
        name = step["with"]["name"]
        assert "test-only" in name or "browser" in name, name
        assert step["with"].get("retention-days"), f"{name} must expire"


# ---------------------------------------------------------------------------
# Negative detection via a mutated copy of the committed workflow
# ---------------------------------------------------------------------------


def _problems(tmp_path: Path, old: str, new: str) -> list[str]:
    return windows_ci_guards(_write_mutated(tmp_path, old, new))


def test_guard_flags_unpinned_action(tmp_path: Path) -> None:
    problems = _problems(tmp_path, f"actions/checkout@{CHECKOUT_SHA}", "actions/checkout@v4")
    assert any("unpinned" in p for p in problems)


def test_guard_flags_secret_reference(tmp_path: Path) -> None:
    mutated = REPO_TEXT + "\n      # env: KEY=${{ secrets.SIGNING_KEY }}\n"
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "windows-ci.yml").write_text(mutated, encoding="utf-8")
    assert any("secrets" in p for p in windows_ci_guards(tmp_path))


def test_guard_flags_forbidden_write_permission(tmp_path: Path) -> None:
    problems = _problems(tmp_path, "contents: read", "contents: read\n  id-token: write")
    assert any("id-token" in p for p in problems)


def test_guard_flags_missing_timeout(tmp_path: Path) -> None:
    problems = _problems(tmp_path, "    timeout-minutes: 15\n", "")
    assert any("timeout-minutes" in p for p in problems)


def test_guard_flags_missing_artifact_retention(tmp_path: Path) -> None:
    problems = _problems(tmp_path, "retention-days: 7", "")
    assert any("retention-days" in p for p in problems)


def test_guard_flags_malformed_yaml(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "windows-ci.yml").write_text("jobs: [unclosed\n", encoding="utf-8")
    assert any("does not parse" in p for p in windows_ci_guards(tmp_path))
