"""Linux CI workflow contract (provenance + SHA pins)."""

from __future__ import annotations

from pathlib import Path
from typing import Final

import yaml

from licenselens.windows_ci import action_is_pinned

WORKFLOW_FILE: Final = ".github/workflows/ci.yml"
DOCS_FRESHNESS_FILE: Final = ".github/workflows/docs-freshness.yml"
PROVENANCE_SCAN: Final = "scripts/provenance_scan.py"

REQUIRED_JOBS: Final = ("test", "build", "report-browser")
SUPPORTED_PYTHON: Final = ("3.12", "3.13")
_FORBIDDEN_WRITE: Final = ("id-token", "packages", "attestations", "pages")


def _all_steps(jobs: dict) -> list[tuple[str, dict]]:
    steps: list[tuple[str, dict]] = []
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps", []):
            if isinstance(step, dict):
                steps.append((job_name, step))
    return steps


def _run_text(step: dict) -> str:
    run = step.get("run")
    if isinstance(run, str):
        return run
    if isinstance(run, list):
        return "\n".join(str(item) for item in run)
    return ""


def _job_runs(job: dict, needle: str) -> bool:
    for step in job.get("steps", []) if isinstance(job, dict) else []:
        if isinstance(step, dict) and needle in _run_text(step):
            return True
    return False


def _matrix_python_versions(job: dict) -> set[str]:
    strategy = job.get("strategy") if isinstance(job, dict) else {}
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else {}
    versions = matrix.get("python-version") if isinstance(matrix, dict) else None
    if versions is None:
        return set()
    if isinstance(versions, str):
        versions = [versions]
    return {str(v) for v in versions}


def ci_guards(repo_root: Path) -> list[str]:
    path = repo_root / WORKFLOW_FILE
    if not path.is_file():
        return [f"missing workflow file: {WORKFLOW_FILE}"]

    text = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return [f"workflow YAML does not parse: {exc}"]
    if not isinstance(data, dict):
        return ["workflow must be a YAML mapping"]

    problems: list[str] = []

    perms = data.get("permissions")
    if not isinstance(perms, dict):
        problems.append("workflow: missing top-level permissions block")
    else:
        if perms.get("contents") != "read":
            problems.append("workflow: 'contents' permission must be 'read'")
        for key in _FORBIDDEN_WRITE:
            if perms.get(key) == "write":
                problems.append(f"workflow: '{key}' must not be write")

    if "${{ secrets." in text:
        problems.append(
            "workflow: references a secrets expression on the test path "
            "(fork PRs must not reach credentials)"
        )

    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return problems + ["workflow: missing jobs mapping"]

    for name in REQUIRED_JOBS:
        if name not in jobs:
            problems.append(f"workflow: missing required job '{name}'")

    for jname, step in _all_steps(jobs):
        uses = step.get("uses")
        if uses and not action_is_pinned(uses):
            problems.append(f"job '{jname}': unpinned action '{uses}'")

    test_job = jobs.get("test", {}) if isinstance(jobs.get("test"), dict) else {}
    matrix = _matrix_python_versions(test_job)
    for version in SUPPORTED_PYTHON:
        if version not in matrix:
            problems.append(f"workflow: test job must run on Python {version}")

    build = jobs.get("build", {}) if isinstance(jobs.get("build"), dict) else {}
    if not _job_runs(build, PROVENANCE_SCAN):
        problems.append("job 'build': must run provenance_scan.py")
    if not _job_runs(build, "--workspace"):
        problems.append("job 'build': must run provenance_scan --workspace before build")
    if not _job_runs(build, "--artifacts"):
        problems.append("job 'build': must run provenance_scan --artifacts after build")

    if not _job_runs(test_job, PROVENANCE_SCAN) or not _job_runs(test_job, "--workspace"):
        problems.append("job 'test': must run provenance_scan --workspace")

    build_steps = [s for s in build.get("steps", []) if isinstance(s, dict)]
    workspace_idx = next(
        (i for i, s in enumerate(build_steps) if "--workspace" in _run_text(s)),
        None,
    )
    build_idx = next(
        (i for i, s in enumerate(build_steps) if "python -m build" in _run_text(s)),
        None,
    )
    artifacts_idx = next(
        (i for i, s in enumerate(build_steps) if "--artifacts" in _run_text(s)),
        None,
    )
    if workspace_idx is None or build_idx is None or workspace_idx >= build_idx:
        problems.append("job 'build': --workspace provenance scan must run before build")
    if artifacts_idx is None or build_idx is None or artifacts_idx <= build_idx:
        problems.append("job 'build': --artifacts provenance scan must run after build")

    return problems


def docs_freshness_guards(repo_root: Path) -> list[str]:
    path = repo_root / DOCS_FRESHNESS_FILE
    if not path.is_file():
        return [f"missing workflow file: {DOCS_FRESHNESS_FILE}"]

    text = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return [f"docs-freshness YAML does not parse: {exc}"]
    if not isinstance(data, dict):
        return ["docs-freshness workflow must be a YAML mapping"]

    problems: list[str] = []
    perms = data.get("permissions")
    if not isinstance(perms, dict) or perms.get("contents") != "read":
        problems.append("docs-freshness: top-level contents must be read")
    if "${{ secrets." in text:
        problems.append("docs-freshness: must not reference secrets expressions")

    jobs = data.get("jobs") if isinstance(data.get("jobs"), dict) else {}
    for jname, step in _all_steps(jobs):
        uses = step.get("uses")
        if uses and not action_is_pinned(uses):
            problems.append(f"docs-freshness job '{jname}': unpinned action '{uses}'")

    joined = "\n".join(
        _run_text(step)
        for job in jobs.values()
        if isinstance(job, dict)
        for step in job.get("steps", [])
        if isinstance(step, dict)
    )
    if PROVENANCE_SCAN not in joined or "--workspace" not in joined:
        problems.append("docs-freshness: must run provenance_scan --workspace on generated docs")
    return problems
