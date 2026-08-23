"""Tests for surfacing per-check compliance ``mappings:`` in the reference docs.

Covers the G2 surface-compliance-mappings work: the generated ``checks.md``
carries a Mappings column sourced from each check's optional ``mappings:``
block, checks without mappings render the em-dash placeholder (never an
error), and the freshness check stays green after regeneration.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from licenselens.catalog.reference import build_reference_model

ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = ROOT / "scripts" / "generate_reference_docs.py"


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location("generate_reference_docs", GENERATOR_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["generate_reference_docs"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gen(mod):
    return mod.build_generation()


def test_checks_md_has_mappings_column(mod, gen) -> None:
    checks = gen.reference_files["checks.md"]
    header = next(line for line in checks.splitlines() if line.startswith("| Check ID"))
    assert "Mappings" in header, "checks.md table header is missing the Mappings column"


def test_mapped_check_shows_nist_and_mitre_ids(mod, gen) -> None:
    checks = gen.reference_files["checks.md"]
    row = next(line for line in checks.splitlines() if "`id-ca-mfa-all-users`" in line)
    assert "NIST: AC-2, IA-2" in row, "id-ca-mfa-all-users missing its NIST ids"
    assert "MITRE: T1078" in row, "id-ca-mfa-all-users missing its MITRE id"


def test_unmapped_check_renders_placeholder(mod, gen) -> None:
    model = build_reference_model()
    unmapped = next(c for c in model.checks if not c.mappings)
    checks = gen.reference_files["checks.md"]
    row = next(line for line in checks.splitlines() if f"`{unmapped.id}`" in line)
    assert "—" in row, f"unmapped check {unmapped.id!r} did not render the em-dash placeholder"


def test_reference_json_carries_mappings(mod, gen) -> None:
    import json

    data = json.loads(gen.reference_files["reference.json"])
    by_id = {c["id"]: c for c in data["checks"]}
    assert by_id["id-ca-mfa-all-users"]["mappings"] == {
        "nist": ["AC-2", "IA-2"],
        "mitre": ["T1078"],
    }
    assert by_id["az-cspm-out-of-scope"]["mappings"] == {}


def test_fresh_tree_passes_check(mod, gen, tmp_path: Path) -> None:
    mod.write_generation(gen, tmp_path)
    assert mod.check_generation(gen, tmp_path) == []


def test_check_mode_exits_zero(mod, gen, tmp_path: Path, capsys) -> None:
    mod.write_generation(gen, tmp_path)
    code = mod.main(["--check", "--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "PASS" in out
    assert "FAIL" not in out


def test_report_renders_mappings_facet_and_em_dash_for_unmapped(tmp_path: Path) -> None:
    from licenselens.report.html import write_html_report
    from tests.report_fixtures import comprehensive_report

    result = comprehensive_report()
    result.findings[0].mappings = {"nist": ["AC-2", "IA-2"], "mitre": ["T1078"]}
    html = write_html_report(result, tmp_path / "report.html").read_text(encoding="utf-8")

    assert 'data-facet="mappings"' in html
    mapped_row = next(
        line for line in html.splitlines() if 'data-check-id="id-ca-priv-gaps"' in line
    )
    assert "data-mappings=" in mapped_row
    assert "NIST: AC-2, IA-2" in mapped_row
    assert "MITRE: T1078" in mapped_row
    assert "Compliance: MITRE: T1078; NIST: AC-2, IA-2" in html
    assert 'data-mappings="—"' in html
