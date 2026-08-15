"""RED contract: provenance scanner module + contamination policy (todo 5 gate).

The scanner does not exist yet. An uncaught ImportError is the intentional RED
signature. The body already encodes the full post-implementation assertions.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _competitor_token_from_readme() -> str:
    """Derive the sole allowed comparison-table token structurally from README.md."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    lines = readme.splitlines()
    in_table = False
    for line in lines:
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
            if match is None:
                raise AssertionError(
                    "README comparison row for CSPM tool lacks markdown link structure"
                )
            return match.group(1).strip()
    raise AssertionError("README comparison table CSPM row not found structurally")


def _load_provenance_scanner() -> Any:
    """Import licenselens.provenance or scripts/provenance_scan.py directly."""
    try:
        return importlib.import_module("licenselens.provenance")
    except ImportError:
        pass

    script = ROOT / "scripts" / "provenance_scan.py"
    if script.is_file():
        spec = importlib.util.spec_from_file_location("provenance_scan", script)
        if spec is None or spec.loader is None:
            raise ImportError("unable to load scripts/provenance_scan.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules["provenance_scan"] = module
        spec.loader.exec_module(module)
        return module

    return importlib.import_module("scripts.provenance_scan")


def _scan_api(scanner: Any) -> Any:
    for name in ("scan_workspace", "run_scan", "scan", "main_scan"):
        func = getattr(scanner, name, None)
        if callable(func):
            return func
    raise AssertionError(
        "provenance scanner must expose scan_workspace/run_scan/scan callable"
    )


def _findings(result: Any) -> list[Any]:
    if result is None:
        return []
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        for key in ("findings", "hits", "violations", "problems"):
            value = result.get(key)
            if isinstance(value, list):
                return value
        return [result] if result.get("status") not in {None, "ok", "pass", "clean"} else []
    status = getattr(result, "status", None)
    if status in {"ok", "pass", "clean", 0}:
        return list(getattr(result, "findings", []) or getattr(result, "hits", []) or [])
    hits = getattr(result, "findings", None) or getattr(result, "hits", None)
    if hits is not None:
        return list(hits)
    return [result]


def _is_clean_except_readme(findings: list[Any], readme: Path) -> bool:
    if not findings:
        return True
    readme_name = readme.name
    for item in findings:
        text = str(item).lower()
        if readme_name.lower() not in text and "readme" not in text:
            return False
    return True


def test_provenance_scanner_rejects_contamination_allows_readme_row_only(
    tmp_path: Path,
) -> None:
    """Full policy body; RED today is ImportError from the missing scanner module."""
    scanner = _load_provenance_scanner()
    scan = _scan_api(scanner)
    token = _competitor_token_from_readme()
    assert token, "structurally derived comparison token must be non-empty"
    source_text = Path(__file__).read_text(encoding="utf-8")
    assert token not in source_text, (
        "test source must not embed the prohibited competitor token literally"
    )

    clean = tmp_path / "clean"
    clean.mkdir()
    readme = clean / "README.md"
    readme.write_text(
        "# Product\n\n| Tool | Optimizes for |\n|------|----------------|\n"
        f"| [{token}](https://github.com/example/{token}) | Broad CSPM / CIS-style assessment |\n"
        "| **Security License Lens** | Owned SKUs gaps |\n",
        encoding="utf-8",
    )
    (clean / "src").mkdir()
    (clean / "src" / "ok.py").write_text("print('hello')\n", encoding="utf-8")

    clean_result = scan(clean)
    findings = _findings(clean_result)
    assert _is_clean_except_readme(findings, readme), (
        f"clean fixture must permit exactly the README comparison row; got {findings!r}"
    )

    dirty_text = tmp_path / "dirty_text"
    dirty_text.mkdir()
    (dirty_text / "NOTES.md").write_text(f"see {token} for comparison\n", encoding="utf-8")
    assert _findings(scan(dirty_text)), "text contamination must be rejected"

    dirty_path = tmp_path / "dirty_path"
    dirty_path.mkdir()
    bad_dir = dirty_path / f"vendor-{token.lower()}"
    bad_dir.mkdir()
    (bad_dir / "x.txt").write_text("ok\n", encoding="utf-8")
    assert _findings(scan(dirty_path)), "path-component contamination must be rejected"

    dirty_arch = tmp_path / "dirty_arch"
    dirty_arch.mkdir()
    archive = dirty_arch / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("inner/readme.txt", f"contaminated {token}\n")
    assert _findings(scan(dirty_arch)), "archive member contamination must be rejected"

    dirty_bin = tmp_path / "dirty_bin"
    dirty_bin.mkdir()
    (dirty_bin / "payload.bin").write_bytes(
        b"header\x00" + token.encode("utf-8") + b"\x00trailer"
    )
    assert _findings(scan(dirty_bin)), "binary string contamination must be rejected"

    dirty_git = tmp_path / "dirty_git"
    dirty_git.mkdir()
    (dirty_git / ".git_messages.txt").write_text(
        f"commit: align with {token} maturity work\n",
        encoding="utf-8",
    )
    assert _findings(scan(dirty_git)), "git-metadata-style contamination must be rejected"

    allowed_row = next(
        line
        for line in (ROOT / "README.md").read_text(encoding="utf-8").splitlines()
        if "CSPM" in line or "CIS-style" in line
    )
    row_digest = hashlib.sha256(allowed_row.strip().encode("utf-8")).hexdigest()
    assert len(row_digest) == 64
