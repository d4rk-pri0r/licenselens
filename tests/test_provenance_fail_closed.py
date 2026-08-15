"""Fail-closed behavior: malformed archives and broken symlinks."""

from __future__ import annotations

import re
from pathlib import Path

from licenselens.provenance import scan_workspace
from licenselens.provenance.models import ViolationKind

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


def test_truncated_zip_is_violation(tmp_path: Path) -> None:
    root = tmp_path / "badzip"
    root.mkdir()
    # Truncated / invalid zip bytes.
    (root / "broken.zip").write_bytes(b"PK\x03\x04truncated")
    result = scan_workspace(root, policy_readme=ROOT / "README.md")
    assert result.status == "violations"
    assert any(v.kind is ViolationKind.MALFORMED_ARCHIVE for v in result.violations)


def test_truncated_tar_is_violation(tmp_path: Path) -> None:
    root = tmp_path / "badtar"
    root.mkdir()
    (root / "broken.tar").write_bytes(b"ustar\x00not-a-real-tar")
    result = scan_workspace(root, policy_readme=ROOT / "README.md")
    assert result.status == "violations"
    assert any(v.kind is ViolationKind.MALFORMED_ARCHIVE for v in result.violations)


def test_broken_symlink_is_violation(tmp_path: Path) -> None:
    root = tmp_path / "symlink"
    root.mkdir()
    link = root / "dangling"
    link.symlink_to("missing-target-does-not-exist")
    result = scan_workspace(root, policy_readme=ROOT / "README.md")
    assert result.status == "violations"
    assert any(v.kind is ViolationKind.UNREADABLE for v in result.violations)


def test_symlink_target_with_token_is_violation(tmp_path: Path) -> None:
    token = _token()
    root = tmp_path / "symlink_token"
    root.mkdir()
    target = root / "real.txt"
    target.write_text("ok\n", encoding="utf-8")
    link = root / "link"
    link.symlink_to(f"real-{token}.txt")
    result = scan_workspace(root, policy_readme=ROOT / "README.md")
    assert result.status == "violations"
    assert any(v.kind is ViolationKind.SYMLINK_TARGET for v in result.violations)
