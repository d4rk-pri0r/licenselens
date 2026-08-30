"""Python-only publish workflow contract (T7).

Static guards over ``.github/workflows/publish-python.yml``, the minimal
manual-dispatch path that publishes wheel + sdist to PyPI:

  * manual dispatch only (no push / pull_request / tag / schedule triggers),
  * wheel + sdist only (no Windows one-folder, no SBOM / attestation surface),
  * every action pinned by a full commit SHA reused from publish.yml,
  * least privilege: top-level ``contents: read``; ``id-token: write`` only on
    the publish job that performs PyPI trusted publishing (OIDC),
  * publish downloads the built artifacts and never rebuilds.

These tests only validate the file; the workflow runs on GitHub-hosted
runners. The gated multi-surface pipeline stays locked by
``tests/test_release_guard.py``; this module adds to it without weakening it.
"""

from __future__ import annotations

from pathlib import Path

from licenselens.release_guard import WORKFLOW_FILE, load_workflow
from licenselens.windows_ci import action_is_pinned

REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON_WORKFLOW_REL = ".github/workflows/publish-python.yml"
PYTHON_WORKFLOW_PATH = REPO_ROOT / PYTHON_WORKFLOW_REL
REPO_TEXT = PYTHON_WORKFLOW_PATH.read_text(encoding="utf-8")

#: Actions publish-python.yml must reuse, pinned exactly as in publish.yml.
REQUIRED_ACTIONS = (
    "actions/checkout",
    "actions/setup-python",
    "actions/upload-artifact",
    "actions/download-artifact",
    "pypa/gh-action-pypi-publish",
)

#: Surfaces this minimal pipeline must NOT touch (publish.yml territory).
FORBIDDEN_ACTION_FRAGMENTS = (
    "trusted-signing-action",
    "sbom-action",
    "attest-build-provenance",
    "attest-sbom",
    "action-gh-release",
)


def _load() -> dict:
    return load_workflow(REPO_TEXT)


def _load_gated_release() -> dict:
    return load_workflow((REPO_ROOT / WORKFLOW_FILE).read_text(encoding="utf-8"))


def _pins_from_release(data: dict) -> dict[str, str]:
    """Map ``owner/repo -> pinned SHA`` for every action in the release workflow."""
    pins: dict[str, str] = {}
    for job in data["jobs"].values():
        for step in job.get("steps", []):
            uses = step.get("uses", "") if isinstance(step, dict) else ""
            if uses and "@" in uses:
                action, _, ref = uses.rpartition("@")
                pins.setdefault(action, ref)
    return pins


def _steps_of(job: dict) -> list[dict]:
    return [s for s in job.get("steps", []) if isinstance(s, dict)]


def _runs_of(job: dict) -> str:
    return "\n".join(s.get("run", "") for s in _steps_of(job))


def _uses_of(data: dict) -> list[str]:
    return [
        s.get("uses", "")
        for job in data["jobs"].values()
        for s in _steps_of(job)
        if s.get("uses")
    ]


def _job_permission(job: dict, key: str) -> str | None:
    perms = job.get("permissions")
    if not isinstance(perms, dict):
        return None
    return perms.get(key)


# ---------------------------------------------------------------------------
# Guard function over an already-parsed workflow
# ---------------------------------------------------------------------------


def python_publish_guards(data: dict, *, release_pins: dict[str, str]) -> list[str]:
    """Static guards over the python-only publish workflow; [] means all pass."""
    problems: list[str] = []

    # --- manual dispatch only ---------------------------------------------
    on = data.get("on")
    if not isinstance(on, dict) or "workflow_dispatch" not in on:
        problems.append("workflow: must trigger on workflow_dispatch (manual)")
    for forbidden in ("push", "pull_request", "schedule", "release"):
        if isinstance(on, dict) and forbidden in on:
            problems.append(f"workflow: must not trigger on {forbidden}")

    # --- minimal top-level permissions -------------------------------------
    perms = data.get("permissions")
    if not isinstance(perms, dict) or perms.get("contents") != "read":
        problems.append("workflow: top-level 'contents' must be 'read'")
    if isinstance(perms, dict) and perms.get("id-token") == "write":
        problems.append("workflow: top-level 'id-token' must not be write")

    # --- jobs ---------------------------------------------------------------
    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or set(jobs) != {"build", "publish"}:
        problems.append("workflow: must contain exactly the jobs 'build' and 'publish'")
        return problems

    build = jobs["build"]
    publish = jobs["publish"]

    # --- every action SHA-pinned and reused from publish.yml ----------------
    for uses in _uses_of(data):
        if not uses:
            continue
        action, _, ref = uses.rpartition("@")
        if not action_is_pinned(uses):
            problems.append(f"workflow: unpinned action '{uses}'")
            continue
        if action not in release_pins:
            problems.append(f"workflow: action '{action}' is not used by {WORKFLOW_FILE}")
        elif release_pins[action] != ref:
            problems.append(
                f"workflow: action '{action}' pinned {ref!r} but publish.yml pins "
                f"{release_pins[action]!r} (SHAs must be reused, not diverged)"
            )
    for action in REQUIRED_ACTIONS:
        if not any(u.startswith(f"{action}@") for u in _uses_of(data)):
            problems.append(f"workflow: missing required action '{action}'")

    # --- wheel + sdist only: build once, no other surfaces -------------------
    build_runs = _runs_of(build)
    if "python -m build" not in build_runs:
        problems.append("job 'build': must run 'python -m build' (sdist + wheel)")
    all_text = REPO_TEXT
    for fragment in FORBIDDEN_ACTION_FRAGMENTS:
        if any(fragment in u for u in _uses_of(data)):
            problems.append(
                f"workflow: '{fragment}' belongs to the gated release pipeline, not this one"
            )
    if "pyinstaller" in all_text or "build-windows" in jobs:
        problems.append("workflow: wheel+sdist only — no Windows surface allowed")

    # --- publish: download-only, trusted publishing, least privilege --------
    if "build" not in (publish.get("needs") or []):
        problems.append("job 'publish': needs must include 'build'")
    if not any("download-artifact" in u for u in _uses_of({"jobs": {"publish": publish}})):
        problems.append("job 'publish': must download the built artifacts")
    if not any("pypi-publish" in u for u in _uses_of({"jobs": {"publish": publish}})):
        problems.append("job 'publish': must publish via pypa/gh-action-pypi-publish")
    if _job_permission(publish, "id-token") != "write":
        problems.append("job 'publish': must request id-token: write (PyPI trusted publishing)")
    publish_runs = _runs_of(publish)
    if "python -m build" in publish_runs or "pyinstaller" in publish_runs:
        problems.append("job 'publish': must not rebuild artifacts")
    if not publish.get("environment"):
        problems.append("job 'publish': must declare a protected environment (pypi)")

    return problems


def _guards() -> list[str]:
    return python_publish_guards(_load(), release_pins=_pins_from_release(_load_gated_release()))


def _mutated(old: str, new: str, *, count: int = 1) -> dict:
    assert old in REPO_TEXT, f"marker not found: {old!r}"
    return load_workflow(REPO_TEXT.replace(old, new, count))


def _problems(old: str, new: str) -> list[str]:
    return python_publish_guards(
        _mutated(old, new),
        release_pins=_pins_from_release(_load_gated_release()),
    )


# ---------------------------------------------------------------------------
# Happy path: the committed workflow passes every guard
# ---------------------------------------------------------------------------


def test_committed_workflow_passes_all_guards() -> None:
    assert _guards() == []


def test_release_guards_still_hold_for_gated_pipeline() -> None:
    # This module must not weaken the release-of-record pipeline's contract.
    from licenselens.release_guard import release_guards

    assert release_guards(REPO_ROOT) == []


# ---------------------------------------------------------------------------
# Triggers, permissions
# ---------------------------------------------------------------------------


def test_workflow_is_manual_dispatch_only() -> None:
    on = _load()["on"]
    assert "workflow_dispatch" in on
    for forbidden in ("push", "pull_request", "schedule", "release"):
        assert forbidden not in on, forbidden


def test_top_level_permissions_are_minimal() -> None:
    assert _load()["permissions"] == {"contents": "read"}


def test_id_token_is_publish_job_scoped() -> None:
    data = _load()
    assert data["permissions"].get("id-token") != "write"
    assert data["jobs"]["publish"]["permissions"]["id-token"] == "write"
    assert "permissions" not in data["jobs"]["build"]


# ---------------------------------------------------------------------------
# Action pinning: reuse publish.yml SHAs exactly
# ---------------------------------------------------------------------------


def test_every_action_is_sha_pinned() -> None:
    for uses in _uses_of(_load()):
        assert uses is None or action_is_pinned(uses), uses


def test_every_action_sha_is_reused_from_publish_yml() -> None:
    pins = _pins_from_release(_load_gated_release())
    for uses in _uses_of(_load()):
        action, _, ref = uses.rpartition("@")
        assert action in pins, f"'{action}' is not used by {WORKFLOW_FILE}"
        assert ref == pins[action], (uses, pins[action])


def test_required_actions_are_present() -> None:
    uses = _uses_of(_load())
    for action in REQUIRED_ACTIONS:
        assert any(u.startswith(f"{action}@") for u in uses), action


# ---------------------------------------------------------------------------
# Topology: wheel + sdist only, build once, publish downloads
# ---------------------------------------------------------------------------


def test_build_produces_wheel_and_sdist() -> None:
    runs = _runs_of(_load()["jobs"]["build"])
    assert "python -m build" in runs
    upload_paths = "\n".join(
        str(step.get("with", {}).get("path", ""))
        for step in _steps_of(_load()["jobs"]["build"])
        if "upload-artifact" in step.get("uses", "")
    )
    assert "*.whl" in upload_paths
    assert "*.tar.gz" in upload_paths


def test_no_windows_or_sbom_or_attestation_surface() -> None:
    data = _load()
    for fragment in FORBIDDEN_ACTION_FRAGMENTS:
        assert not any(fragment in u for u in _uses_of(data)), fragment
    assert "pyinstaller" not in REPO_TEXT
    assert "build-windows" not in data["jobs"]


def test_publish_needs_build_and_downloads() -> None:
    publish = _load()["jobs"]["publish"]
    assert "build" in (publish.get("needs") or [])
    uses = [s.get("uses", "") for s in _steps_of(publish)]
    assert any("download-artifact" in u for u in uses)


def test_publish_uses_trusted_publishing_in_protected_environment() -> None:
    publish = _load()["jobs"]["publish"]
    uses = [s.get("uses", "") for s in _steps_of(publish)]
    assert any("pypi-publish" in u for u in uses)
    assert publish.get("environment"), "publish must target a protected environment"


def test_publish_never_rebuilds() -> None:
    runs = _runs_of(_load()["jobs"]["publish"])
    assert "python -m build" not in runs
    assert "pyinstaller" not in runs


# ---------------------------------------------------------------------------
# Negative detection via mutated copies of the committed workflow
# ---------------------------------------------------------------------------


def test_guard_flags_unpinned_action() -> None:
    sha = "f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a"
    problems = _problems(f"actions/checkout@{sha}", "actions/checkout@v4")
    assert any("unpinned" in p for p in problems)


def test_guard_flags_diverged_sha() -> None:
    old = "actions/setup-python@8549b9f8f590ad24eab7482f36f6e1e24d34597b"
    new = "actions/setup-python@8549b9f8f590ad24eab7482f36f6e1e24d34597c"
    problems = _problems(old, new)
    assert any("SHAs must be reused" in p for p in problems)


def test_guard_flags_push_trigger() -> None:
    problems = _problems(
        "on:\n  workflow_dispatch: {}",
        "on:\n  workflow_dispatch: {}\n  push:\n    branches: [main]",
    )
    assert any("push" in p for p in problems)


def test_guard_flags_missing_dispatch() -> None:
    problems = _problems(
        "on:\n  workflow_dispatch: {}",
        "on:\n  schedule:\n    - cron: '0 0 * * *'",
    )
    assert any("workflow_dispatch" in p for p in problems)
    assert any("schedule" in p for p in problems)


def test_guard_flags_top_level_id_token_write() -> None:
    problems = _problems(
        "permissions:\n  contents: read",
        "permissions:\n  contents: read\n  id-token: write",
    )
    assert any("top-level 'id-token'" in p for p in problems)


def test_guard_flags_publish_without_id_token() -> None:
    problems = _problems("      id-token: write\n", "")
    assert any("id-token: write (PyPI trusted publishing)" in p for p in problems)


def test_guard_flags_publish_rebuild() -> None:
    problems = _problems(
        "      - name: Publish to PyPI (trusted publishing / OIDC)",
        "      - name: rebuild\n        run: python -m build\n"
        "      - name: Publish to PyPI (trusted publishing / OIDC)",
    )
    assert any("must not rebuild" in p for p in problems)
