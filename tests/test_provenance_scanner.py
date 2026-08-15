"""Integration tests for workspace / artifacts / git provenance modes."""

from __future__ import annotations

import json
import re
import subprocess
import zipfile
from pathlib import Path

from licenselens.provenance import (
    ScanMode,
    result_to_json,
    run_scan,
    scan_artifacts,
    scan_workspace,
)

ROOT = Path(__file__).resolve().parents[1]


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


def _clean_tree(base: Path) -> Path:
    token = _token()
    base.mkdir(parents=True, exist_ok=True)
    (base / "README.md").write_text(
        "# Product\n\n| Tool | Optimizes for |\n|------|----------------|\n"
        f"| [{token}](https://github.com/example/{token}) | Broad CSPM / CIS-style assessment |\n"
        "| **Security License Lens** | Owned SKUs gaps |\n",
        encoding="utf-8",
    )
    (base / "src").mkdir()
    (base / "src" / "ok.py").write_text("print('hello')\n", encoding="utf-8")
    return base


def test_clean_workspace_is_clean(tmp_path: Path) -> None:
    clean = _clean_tree(tmp_path / "clean")
    result = scan_workspace(clean)
    assert result.status == "clean"
    assert result.violations == ()
    assert result.mode is ScanMode.WORKSPACE


def test_text_path_archive_binary_rejected(tmp_path: Path) -> None:
    token = _token()

    dirty_text = tmp_path / "dirty_text"
    dirty_text.mkdir()
    (dirty_text / "NOTES.md").write_text(f"see {token} for comparison\n", encoding="utf-8")
    assert scan_workspace(dirty_text).status == "violations"

    dirty_path = tmp_path / "dirty_path"
    dirty_path.mkdir()
    bad_dir = dirty_path / f"vendor-{token.lower()}"
    bad_dir.mkdir()
    (bad_dir / "x.txt").write_text("ok\n", encoding="utf-8")
    assert scan_workspace(dirty_path).status == "violations"

    dirty_arch = tmp_path / "dirty_arch"
    dirty_arch.mkdir()
    archive = dirty_arch / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("inner/readme.txt", f"contaminated {token}\n")
    assert scan_workspace(dirty_arch).status == "violations"

    dirty_bin = tmp_path / "dirty_bin"
    dirty_bin.mkdir()
    (dirty_bin / "payload.bin").write_bytes(
        b"header\x00" + token.encode("utf-8") + b"\x00trailer"
    )
    result = scan_workspace(dirty_bin)
    assert result.status == "violations"
    assert any(v.snippet_hex for v in result.violations)


def test_artifacts_mode_scans_wheel_member(tmp_path: Path) -> None:
    token = _token()
    root = tmp_path / "arts"
    root.mkdir()
    wheel = root / "pkg-0.0.1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("pkg/data.txt", f"has {token}\n")
    result = scan_artifacts(root, policy_readme=ROOT / "README.md")
    assert result.status == "violations"
    assert any(v.member for v in result.violations)


def test_json_output_deterministic_and_sorted(tmp_path: Path) -> None:
    clean = _clean_tree(tmp_path / "clean")
    result = scan_workspace(clean)
    a = result_to_json(result)
    b = result_to_json(result)
    assert a == b
    payload = json.loads(a)
    assert list(payload.keys()) == sorted(payload.keys())
    assert "timestamp" not in a
    assert payload["status"] == "clean"


def test_run_scan_mode_dispatch(tmp_path: Path) -> None:
    clean = _clean_tree(tmp_path / "clean")
    result = run_scan(clean, mode="workspace")
    assert result.status == "clean"


def test_git_reachable_detects_commit_message(tmp_path: Path) -> None:
    token = _token()
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "dev@example.com"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Dev"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    (repo / "README.md").write_text(
        "# Product\n\n| Tool | Optimizes for |\n|------|----------------|\n"
        f"| [{token}](https://github.com/example/{token}) | Broad CSPM / CIS-style assessment |\n",
        encoding="utf-8",
    )
    (repo / "ok.txt").write_text("ok\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", f"align with {token} maturity"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    result = run_scan(repo, mode=ScanMode.GIT_REACHABLE)
    assert result.status == "violations"
    assert any(v.kind.value == "git_message" for v in result.violations)


def test_git_note_detected(tmp_path: Path) -> None:
    token = _token()
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "dev@example.com"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Dev"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    (repo / "a.txt").write_text("ok\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "notes", "add", "-m", f"note about {token}", head],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    result = run_scan(
        repo,
        mode=ScanMode.GIT_REACHABLE,
        policy_readme=ROOT / "README.md",
    )
    assert result.status == "violations"
