"""Performance smoke tests for batched git provenance scans."""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

from licenselens.provenance import ScanMode, run_scan

ROOT = Path(__file__).resolve().parents[1]
_PERF_BUDGET_S = 20.0
_COMMIT_COUNT = 300


def _token() -> str:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    in_table = False
    for line in readme.splitlines():
        if line.startswith("| Tool |") or line.startswith("|Tool|"):
            in_table = True
            continue
        if not in_table:
            continue
        if not line.startswith("|"):
            break
        if re.match(r"^\|\s*-+", line):
            continue
        if "CSPM" in line or "CIS-style" in line:
            match = re.search(r"\[([^\]]+)\]\((https://github\.com/[^)]+)\)", line)
            assert match is not None
            return match.group(1).strip()
    raise AssertionError("token row missing")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _build_history_repo(base: Path) -> Path:
    """Synthetic repo: ~300 commits, seeded contamination in one historical blob."""
    token = _token()
    repo = base / "perf-repo"
    repo.mkdir(parents=True)
    _git(repo, "init")
    _git(repo, "config", "user.email", "perf@example.com")
    _git(repo, "config", "user.name", "Perf")

    (repo / "README.md").write_text(
        "# Product\n\n| Tool | Optimizes for |\n|------|----------------|\n"
        f"| [{token}](https://github.com/example/{token}) | Broad CSPM / CIS-style assessment |\n"
        "| **Security License Lens** | Owned SKUs gaps |\n",
        encoding="utf-8",
    )
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("print('ok')\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "init clean")

    dirty = repo / "docs" / "notes.md"
    dirty.parent.mkdir(parents=True)
    dirty.write_text(f"historical note about {token}\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "add docs")

    dirty.write_text("cleaned notes\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "scrub docs")

    for index in range(_COMMIT_COUNT):
        target = repo / "src" / f"file_{index % 40}.txt"
        target.write_text(f"payload {index}\n", encoding="utf-8")
        _git(repo, "add", ".")
        _git(repo, "commit", "-m", f"touch {index}")

    return repo


def test_git_scans_finish_under_budget_and_find_seeded_hit(tmp_path: Path) -> None:
    repo = _build_history_repo(tmp_path)

    started = time.perf_counter()
    reachable = run_scan(repo, mode=ScanMode.GIT_REACHABLE, policy_readme=ROOT / "README.md")
    reachable_s = time.perf_counter() - started
    assert reachable_s < _PERF_BUDGET_S, f"git-reachable took {reachable_s:.2f}s"
    assert reachable.status == "violations"
    assert any(v.path.endswith("docs/notes.md") for v in reachable.violations)
    assert any(v.kind.value == "git_object" for v in reachable.violations)

    started = time.perf_counter()
    all_objects = run_scan(
        repo, mode=ScanMode.GIT_ALL_OBJECTS, policy_readme=ROOT / "README.md"
    )
    all_objects_s = time.perf_counter() - started
    assert all_objects_s < _PERF_BUDGET_S, f"git-all-objects took {all_objects_s:.2f}s"
    assert all_objects.status == "violations"
    assert any(v.kind.value == "git_object" for v in all_objects.violations)
