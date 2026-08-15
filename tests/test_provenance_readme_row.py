"""Regression: README allowed-row spans must compare in UTF-8 byte space."""

from __future__ import annotations

from pathlib import Path

from licenselens.provenance.git_ops import scan_readme_blob
from licenselens.provenance.models import ScanMode
from licenselens.provenance.token import load_token_policy, parse_allowed_row
from licenselens.provenance.workspace import _scan_readme_text, scan_workspace_tree

ROOT = Path(__file__).resolve().parents[1]


def _readme_with_multibyte_prefix() -> str:
    real = (ROOT / "README.md").read_text(encoding="utf-8")
    row = parse_allowed_row(real)
    prefix = (
        "Security — the “owned” controls you already pay for.\n\n"
        "| Tool | Optimizes for |\n"
        "|------|----------------|\n"
    )
    return prefix + row.line_text + "\n"


def test_allowed_readme_row_not_flagged_after_multibyte_prefix(tmp_path: Path) -> None:
    text = _readme_with_multibyte_prefix()
    (tmp_path / "README.md").write_text(text, encoding="utf-8")

    policy = load_token_policy(tmp_path)
    hits = _scan_readme_text(
        policy,
        text,
        relative="README.md",
        mode=ScanMode.WORKSPACE,
    )
    assert hits == []

    violations, _scanned = scan_workspace_tree(tmp_path, policy)
    assert violations == []


def test_allowed_readme_row_not_flagged_with_crlf_endings(tmp_path: Path) -> None:
    """Windows autocrlf rewrites README to CRLF; allowed-row bytes must still match."""
    lf_text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "\r\n" not in lf_text
    crlf_text = lf_text.replace("\n", "\r\n")

    lf_row = parse_allowed_row(lf_text)
    crlf_row = parse_allowed_row(crlf_text)
    assert crlf_row.token == lf_row.token
    assert crlf_row.row_sha256 == lf_row.row_sha256
    # CRLF inserts one extra byte per preceding line; span must move with it.
    assert crlf_row.byte_start > lf_row.byte_start
    assert crlf_row.byte_end - crlf_row.byte_start == lf_row.byte_end - lf_row.byte_start

    readme = tmp_path / "README.md"
    readme.write_bytes(crlf_text.encode("utf-8"))
    policy = load_token_policy(tmp_path)

    hits = _scan_readme_text(
        policy,
        crlf_text,
        relative="README.md",
        mode=ScanMode.WORKSPACE,
    )
    assert hits == []

    blob_hits = scan_readme_blob(
        policy,
        crlf_text.encode("utf-8"),
        path="README.md",
        mode=ScanMode.GIT_REACHABLE,
        object_id="crlfdead",
    )
    assert blob_hits == []

    violations, _scanned = scan_workspace_tree(tmp_path, policy)
    assert violations == []


def test_token_outside_allowed_row_still_flagged_under_crlf(tmp_path: Path) -> None:
    """Tamper detection must remain fail-closed when the working tree uses CRLF."""
    token = parse_allowed_row((ROOT / "README.md").read_text(encoding="utf-8")).token
    body = (
        "# Product\n\n"
        "| Tool | Optimizes for |\n"
        "|------|----------------|\n"
        f"| [{token}](https://github.com/silverhack/{token.lower()}) "
        f"| Broad CSPM / CIS-style assessment |\n\n"
        f"Do not ship {token} elsewhere.\n"
    )
    crlf_text = body.replace("\n", "\r\n")
    (tmp_path / "README.md").write_bytes(crlf_text.encode("utf-8"))

    policy = load_token_policy(tmp_path)
    hits = _scan_readme_text(
        policy,
        crlf_text,
        relative="README.md",
        mode=ScanMode.WORKSPACE,
    )
    assert hits, "token outside the allowed row must still violate under CRLF"
    assert all("outside allowed README row" in hit.detail for hit in hits)
