"""Unit tests for runtime token derivation (no literal competitor token)."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from licenselens.provenance.match import path_component_matches, text_matches
from licenselens.provenance.token import (
    EXPECTED_ALLOWED_ROW_SHA256,
    TokenPolicyError,
    load_token_policy,
    normalize_token,
    parse_allowed_row,
)

ROOT = Path(__file__).resolve().parents[1]


def _token_from_repo_readme() -> str:
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
    raise AssertionError("comparison row missing")


def test_parse_allowed_row_from_real_readme_matches_pinned_digest() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    row = parse_allowed_row(text, require_expected_digest=True)
    assert row.matches_expected_digest is True
    assert row.row_sha256 == EXPECTED_ALLOWED_ROW_SHA256
    assert len(row.row_sha256) == 64
    token = _token_from_repo_readme()
    assert row.token == token
    assert "silverhack" in row.url


def test_fixture_cspm_row_derives_token_without_silverhack(tmp_path: Path) -> None:
    token = _token_from_repo_readme()
    readme = tmp_path / "README.md"
    readme.write_text(
        "# Product\n\n| Tool | Optimizes for |\n|------|----------------|\n"
        f"| [{token}](https://github.com/example/{token}) | Broad CSPM / CIS-style assessment |\n",
        encoding="utf-8",
    )
    policy = load_token_policy(tmp_path)
    assert policy.token == token
    assert policy.allowed_row.matches_expected_digest is False


def test_text_matches_case_and_separator_variants() -> None:
    token = _token_from_repo_readme()
    policy = load_token_policy(ROOT)
    assert text_matches(policy, f"see {token} here")
    assert text_matches(policy, f"see {token.upper()} here")
    assert text_matches(policy, f"see {token.lower()} here")
    # Separator-flexible: inject hyphens/spaces into the canonical form.
    canonical = normalize_token(token)
    if len(canonical) >= 4:
        spaced = f"{canonical[:2]}-{canonical[2:]}"
        assert text_matches(policy, f"x {spaced} y")


def test_path_component_match() -> None:
    token = _token_from_repo_readme()
    policy = load_token_policy(ROOT)
    bad = path_component_matches(policy, f"vendor/{token.lower()}/x.txt")
    assert bad
    assert not path_component_matches(policy, "vendor/other/x.txt")


def test_missing_table_raises(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# no table\n", encoding="utf-8")
    with pytest.raises(TokenPolicyError):
        load_token_policy(tmp_path, policy_readme=tmp_path / "README.md")


def test_row_digest_stable() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    row = parse_allowed_row(text)
    recomputed = hashlib.sha256(row.line_text.strip().encode("utf-8")).hexdigest()
    assert recomputed == row.row_sha256


def test_source_and_tests_do_not_embed_token() -> None:
    token = _token_from_repo_readme()
    roots = [
        ROOT / "src" / "licenselens" / "provenance",
        ROOT / "scripts" / "provenance_scan.py",
        ROOT / "tests" / "test_provenance_token.py",
        ROOT / "tests" / "test_provenance_scanner.py",
        ROOT / "tests" / "test_provenance_fail_closed.py",
    ]
    for path in roots:
        if path.is_file():
            assert token not in path.read_text(encoding="utf-8")
            continue
        for file in path.rglob("*.py"):
            assert token not in file.read_text(encoding="utf-8"), file
