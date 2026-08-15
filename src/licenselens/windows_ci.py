"""Windows CI workflow contract (Todo 33).

Cross-platform static guards over ``.github/workflows/windows-ci.yml`` so the
Windows gates are reproducible and the trust invariants are locked without a
Windows runner:

  * every action is pinned by full commit SHA (no floating tags),
  * least privilege (top-level ``contents: read``, no ``id-token``/``packages``
    write),
  * fork-PR secret protection (no ``secrets.*`` reference anywhere on the test
    path),
  * per-job timeouts and a cancel-in-progress concurrency group,
  * required jobs are present (Python 3.12/3.13, Pester, PyInstaller, binary
    smoke, Chromium report), and
  * uploaded test artifacts are explicitly unsigned and expire.

The workflow itself runs on GitHub-hosted Windows runners; this module only
parses/validates it (PyYAML), so it executes anywhere.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import yaml

WORKFLOW_FILE: Final = ".github/workflows/windows-ci.yml"
PROVENANCE_SCAN: Final = "scripts/provenance_scan.py"

#: Jobs the Windows CI is required to run: Python, PowerShell bridge + installer,
#: frozen binary, clean-path smoke, and the Chromium report browser.
REQUIRED_JOBS: Final = (
    "python",
    "powershell",
    "pyinstaller",
    "binary-smoke",
    "report-browser",
)

SUPPORTED_PYTHON: Final = ("3.12", "3.13")

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

#: Permissions that must never be granted write at the workflow top level; the
#: test workflow signs nothing and publishes nothing.
_FORBIDDEN_WRITE: Final = ("id-token", "packages", "attestations", "pages")


def action_is_pinned(uses: str) -> bool:
    """Return True when an action ``uses`` ref is a full 40-char commit SHA."""
    if "@" not in uses:
        return False
    ref = uses.rsplit("@", 1)[1]
    return bool(_SHA_RE.fullmatch(ref))


def _matrix_python_versions(job: dict) -> set[str]:
    strategy = job.get("strategy") if isinstance(job, dict) else {}
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else {}
    versions = matrix.get("python-version") if isinstance(matrix, dict) else None
    if versions is None:
        return set()
    if isinstance(versions, str):
        versions = [versions]
    return {str(v) for v in versions}


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


def windows_ci_guards(repo_root: Path) -> list[str]:
    """Static guards over the Windows CI workflow; an empty list means all pass."""
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

    # --- least privilege -------------------------------------------------
    perms = data.get("permissions")
    if not isinstance(perms, dict):
        problems.append("workflow: missing top-level permissions block")
    else:
        if perms.get("contents") != "read":
            problems.append("workflow: 'contents' permission must be 'read'")
        for key in _FORBIDDEN_WRITE:
            if perms.get(key) == "write":
                problems.append(
                    f"workflow: '{key}' must not be write (test workflow signs nothing)"
                )

    # --- concurrency + cancel-in-progress --------------------------------
    concurrency = data.get("concurrency")
    if not isinstance(concurrency, dict) or "group" not in concurrency:
        problems.append("workflow: missing concurrency group")
    elif concurrency.get("cancel-in-progress") is not True:
        problems.append("workflow: concurrency must set cancel-in-progress: true")

    # --- fork-PR secret protection ----------------------------------------
    # A test workflow must not reference any repository secret expression, so a
    # fork PR can never reach signing/download credentials (those live in the
    # tag-gated release workflow).
    if "${{ secrets." in text:
        problems.append(
            "workflow: references a secrets expression on the test path "
            "(fork PRs must not reach credentials)"
        )

    # --- jobs -------------------------------------------------------------
    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return problems + ["workflow: missing jobs mapping"]

    for name in REQUIRED_JOBS:
        if name not in jobs:
            problems.append(f"workflow: missing required job '{name}'")

    python_job = jobs.get("python", {})
    matrix = _matrix_python_versions(python_job) if isinstance(python_job, dict) else set()
    for version in SUPPORTED_PYTHON:
        if version not in matrix:
            problems.append(f"workflow: python job must run on Python {version}")

    for name, job in jobs.items():
        if not isinstance(job, dict):
            problems.append(f"job '{name}': must be a mapping")
            continue
        if job.get("runs-on") != "windows-latest":
            problems.append(f"job '{name}': runs-on must be windows-latest")
        if not job.get("timeout-minutes"):
            problems.append(f"job '{name}': missing timeout-minutes")
        for _, step in _all_steps({name: job}):
            uses = step.get("uses")
            if uses and not action_is_pinned(uses):
                problems.append(f"job '{name}': unpinned action '{uses}'")

    # --- unsigned, expiring test artifacts --------------------------------
    uploads = [
        (name, step)
        for name, step in _all_steps(jobs)
        if step.get("uses", "").startswith("actions/upload-artifact")
    ]
    if not uploads:
        problems.append("workflow: no upload-artifact step found")
    for name, step in uploads:
        with_args = step.get("with", {}) if isinstance(step.get("with"), dict) else {}
        artifact = str(with_args.get("name", ""))
        if "test-only" not in artifact and "browser" not in artifact:
            problems.append(
                f"job '{name}': artifact '{artifact}' is not labeled unsigned/test-only"
            )
        if not with_args.get("retention-days"):
            problems.append(f"job '{name}': artifact '{artifact}' must set retention-days (expire)")

    # --- provenance scans (tracked sources + built Windows artifacts) -----
    python_job = jobs.get("python", {}) if isinstance(jobs.get("python"), dict) else {}
    pyinstaller = (
        jobs.get("pyinstaller", {}) if isinstance(jobs.get("pyinstaller"), dict) else {}
    )
    if not _job_runs(python_job, PROVENANCE_SCAN) or not _job_runs(python_job, "--workspace"):
        problems.append("job 'python': must run provenance_scan --workspace")
    if not _job_runs(pyinstaller, PROVENANCE_SCAN) or not _job_runs(
        pyinstaller, "--artifacts"
    ):
        problems.append("job 'pyinstaller': must run provenance_scan --artifacts")

    return problems
