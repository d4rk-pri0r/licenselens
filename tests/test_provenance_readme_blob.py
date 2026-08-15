"""Regression: README blob allowed-row spans must compare in UTF-8 byte space."""

from __future__ import annotations

from pathlib import Path

from licenselens.provenance.git_ops import scan_readme_blob
from licenselens.provenance.models import ScanMode
from licenselens.provenance.token import load_token_policy, parse_allowed_row

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


def test_scan_readme_blob_ignores_allowed_row_after_multibyte_prefix(
    tmp_path: Path,
) -> None:
    text = _readme_with_multibyte_prefix()
    (tmp_path / "README.md").write_text(text, encoding="utf-8")

    policy = load_token_policy(tmp_path)
    hits = scan_readme_blob(
        policy,
        text.encode("utf-8"),
        path="README.md",
        mode=ScanMode.GIT_REACHABLE,
        object_id="deadbeef",
    )
    assert hits == []
