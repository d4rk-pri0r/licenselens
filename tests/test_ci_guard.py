"""Continuous-assessment workflow guard tests (Todo G3b).

Lock the trust invariants of ``.github/workflows/continuous-assessment.yml``:
it is scheduled, runs LicenseLens with OIDC workload identity (no stored
client secret), every action is pinned by full commit SHA, and it uploads
machine-readable artifacts. Unlike the CI workflow, this monitoring workflow
legitimately needs ``id-token: write`` to mint a GitHub Actions OIDC token —
so the guard is per-workflow scoped: ``continuous_assessment_guards`` allows
``id-token: write`` here while ``ci_guards`` still rejects it for ci.yml.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from licenselens.ci_guard import (
    CONTINUOUS_ASSESSMENT_FILE,
    WORKFLOW_FILE,
    ci_guards,
    continuous_assessment_guards,
)
from licenselens.windows_ci import action_is_pinned

REPO_ROOT = Path(__file__).resolve().parents[1]
CA_PATH = REPO_ROOT / CONTINUOUS_ASSESSMENT_FILE
CA_TEXT = CA_PATH.read_text(encoding="utf-8")
CI_PATH = REPO_ROOT / WORKFLOW_FILE
CI_TEXT = CI_PATH.read_text(encoding="utf-8")

CHECKOUT_SHA = "f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a"


def _load() -> dict:
    return yaml.safe_load(CA_TEXT)


def _write_mutated(tmp_path: Path, old: str, new: str) -> Path:
    assert old in CA_TEXT, f"marker not found: {old!r}"
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    target = wf_dir / "continuous-assessment.yml"
    target.write_text(CA_TEXT.replace(old, new, 1), encoding="utf-8")
    return tmp_path


def _problems(tmp_path: Path, old: str, new: str) -> list[str]:
    return continuous_assessment_guards(_write_mutated(tmp_path, old, new))


# ---------------------------------------------------------------------------
# Committed workflow passes all guards
# ---------------------------------------------------------------------------


def test_committed_workflow_passes_all_guards() -> None:
    assert continuous_assessment_guards(REPO_ROOT) == []


def test_workflow_has_schedule_and_dispatch_triggers() -> None:
    # PyYAML's YAML 1.1 loader parses the `on:` key as boolean True.
    on = _load().get("on") or _load().get(True)
    assert "schedule" in on
    assert "workflow_dispatch" in on


def test_workflow_grants_id_token_write_for_oidc() -> None:
    perms = _load()["permissions"]
    assert perms["id-token"] == "write"
    assert perms["contents"] == "read"


def test_every_uses_action_in_workflow_is_pinned() -> None:
    data = _load()
    for job_name, job in data["jobs"].items():
        for step in job.get("steps", []):
            uses = step.get("uses")
            assert uses is None or action_is_pinned(uses), (job_name, uses)


def test_workflow_runs_scan_with_oidc_auth() -> None:
    joined = "\n".join(
        step.get("run", "")
        for job in _load()["jobs"].values()
        for step in job.get("steps", [])
        if isinstance(step, dict)
    )
    assert "--auth oidc" in joined


def test_workflow_uploads_report_artifact() -> None:
    data = _load()
    uploads = [
        step
        for job in data["jobs"].values()
        for step in job.get("steps", [])
        if step.get("uses", "").startswith("actions/upload-artifact")
    ]
    assert uploads, "expected at least one upload-artifact step"
    for step in uploads:
        assert step["with"].get("retention-days"), "artifact must expire"


# ---------------------------------------------------------------------------
# Negative detection via a mutated copy of the committed workflow
# ---------------------------------------------------------------------------


def test_guard_flags_unpinned_action(tmp_path: Path) -> None:
    problems = _problems(tmp_path, f"actions/checkout@{CHECKOUT_SHA}", "actions/checkout@v4")
    assert any("unpinned" in p for p in problems)


def test_guard_flags_missing_schedule(tmp_path: Path) -> None:
    problems = _problems(tmp_path, '  schedule:\n    - cron: "30 7 * * *"\n', "")
    assert any("schedule" in p for p in problems)


def test_guard_flags_diff_call(tmp_path: Path) -> None:
    # G8 drift is deferred: the monitoring workflow must not invoke `diff`.
    problems = _problems(
        tmp_path,
        "licenselens scan --auth oidc -o reports --report-archive",
        "licenselens diff reports/before.json reports/after.json -o reports/diff.md",
    )
    assert any("diff" in p for p in problems)


@pytest.mark.parametrize(
    "secret_expr",
    [
        "${{ secrets.EMAIL_WEBHOOK_URL }}",
        "${{ secrets.TEAMS_WEBHOOK_URL }}",
        "${{ secrets.SLACK_WEBHOOK_URL }}",
    ],
)
def test_guard_flags_webhook_secret(tmp_path: Path, secret_expr: str) -> None:
    # G13 is deferred: no Email/Teams/Slack webhook secrets may be added.
    mutated = CA_TEXT + f"\n      # notify: {secret_expr}\n"
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "continuous-assessment.yml").write_text(mutated, encoding="utf-8")
    assert any("secrets" in p for p in continuous_assessment_guards(tmp_path))


def test_guard_flags_malformed_yaml(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "continuous-assessment.yml").write_text("jobs: [unclosed\n", encoding="utf-8")
    assert any("does not parse" in p for p in continuous_assessment_guards(tmp_path))


# ---------------------------------------------------------------------------
# Per-workflow scoping: ci.yml still rejects id-token: write
# ---------------------------------------------------------------------------


def test_ci_workflow_still_rejects_id_token_write(tmp_path: Path) -> None:
    # The monitoring workflow's `id-token: write` must NOT relax the CI guard.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        CI_TEXT.replace("contents: read", "contents: read\n  id-token: write", 1),
        encoding="utf-8",
    )
    problems = ci_guards(tmp_path)
    assert any("id-token" in p for p in problems)


def test_ci_workflow_committed_still_passes() -> None:
    assert ci_guards(REPO_ROOT) == []
