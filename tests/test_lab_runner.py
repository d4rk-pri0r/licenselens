"""Tests for the todo-35 redacted live-lab runner and matrix."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "scripts" / "lab_runner.py"


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location("lab_runner", RUNNER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["lab_runner"] = module
    spec.loader.exec_module(module)
    return module


def test_matrix_validates_clean(mod) -> None:
    problems = mod.validate_matrix(mod.load_matrix())
    assert problems == []


def test_matrix_has_no_identifier_leaks(mod) -> None:
    raw = mod.MATRIX_PATH.read_text(encoding="utf-8")
    assert mod.find_identifier_leaks(raw) == []


def test_every_direct_family_has_pass_and_fail_cases(mod) -> None:
    matrix = mod.load_matrix()
    for family in mod.family_entries(matrix):
        assert family.get("pass_case"), f"{family['id']} missing pass_case"
        assert family.get("fail_case"), f"{family['id']} missing fail_case"
        assert family.get("negative_cases"), f"{family['id']} missing negative_cases"


def test_family_prefixes_partition_all_checks(mod) -> None:
    from licenselens.engine.registry import default_registry

    registry = default_registry()
    known = {entry.id for entry in registry.evaluator_entries}
    by_family = mod.check_ids_by_family()
    covered = {cid for ids in by_family.values() for cid in ids}
    assert covered == known
    assert sum(len(ids) for ids in by_family.values()) == len(known)


def test_downgrades_and_proxies_match_registry(mod) -> None:
    modes = mod.registry_evaluation_modes()
    for family in mod.family_entries(mod.load_matrix()):
        for cid in family.get("downgraded_manual") or []:
            assert modes[cid] == "manual", cid
        for cid in family.get("proxy") or []:
            assert modes[cid] == "proxy", cid
        for cid in family.get("direct_with_proxy_fallback") or []:
            assert modes[cid] == "direct_with_proxy_fallback", cid


def test_pass_probes_all_ok(mod) -> None:
    results = mod.run_pass_probes()
    assert len(results) == 7
    for r in results:
        assert r.observed == "ok", f"{r.probe.family}: {r.observed}"


def test_fail_probes_all_non_ok(mod) -> None:
    results = mod.run_fail_probes()
    assert len(results) == 7
    for r in results:
        assert r.observed in {"gap", "partial", "error"}, f"{r.probe.family}: {r.observed}"


def test_negative_probes_never_ok(mod) -> None:
    results = mod.run_negative_probes()
    assert len(results) == 6
    for r in results:
        assert r.observed != "ok", f"{r.scenario}: {r.observed}"


def test_dry_run_exercises_every_family(mod) -> None:
    coverage = mod.run_dry_run_coverage()
    assert len(coverage) == 7
    for c in coverage:
        assert c.exercised, f"{c.family} not exercised: {c.statuses}"


def test_redact_text_strips_secrets_and_identifiers(mod) -> None:
    sample = (
        "client_secret=abc123 access_token=eyJhbGciOi.jwt.body "
        "user@contoso.com /subscriptions/11111111-2222-3333-4444-555555555555"
    )
    cleaned = mod.redact_text(sample)
    assert mod.find_leaks(cleaned) == []
    assert "abc123" not in cleaned
    assert "contoso.com" not in cleaned


def test_receipts_are_redacted_and_deterministic(mod) -> None:
    matrix = mod.load_matrix()
    pass_results = mod.run_pass_probes()
    fail_results = mod.run_fail_probes()
    coverage = mod.run_dry_run_coverage()
    negative = mod.run_negative_probes()

    first = mod.emit_receipts_text(matrix, pass_results, fail_results, coverage, negative)
    second = mod.emit_receipts_text(matrix, pass_results, fail_results, coverage, negative)
    assert first == second

    for name, content in first.items():
        assert mod.find_leaks(content) == [], name


def test_receipt_command_writes_files(mod, tmp_path: Path) -> None:
    paths = mod.emit_receipts(tmp_path)
    assert (tmp_path / "live-lab.md").is_file()
    assert (tmp_path / "live-lab-negative.md").is_file()
    assert (tmp_path / "live-lab.json").is_file()
    for name in ("live-lab.md", "live-lab-negative.md", "live-lab.json"):
        assert paths[name].read_text(encoding="utf-8").strip()


def test_validate_rejects_unknown_check_id(mod) -> None:
    import copy

    matrix = copy.deepcopy(mod.load_matrix())
    matrix["families"][0]["pass_case"]["checks"][0]["check_id"] = "id-does-not-exist"
    problems = mod.validate_matrix(matrix)
    assert any("unknown check id" in p for p in problems)


def test_validate_rejects_bad_expected_status(mod) -> None:
    import copy

    matrix = copy.deepcopy(mod.load_matrix())
    matrix["families"][0]["fail_case"]["checks"][0]["expected"] = "not_a_status"
    problems = mod.validate_matrix(matrix)
    assert any("bad expected status" in p for p in problems)


def test_validate_rejects_missing_fail_case(mod) -> None:
    import copy

    matrix = copy.deepcopy(mod.load_matrix())
    matrix["families"][3].pop("fail_case")
    problems = mod.validate_matrix(matrix)
    assert any("missing fail_case" in p for p in problems)


def test_validate_rejects_wrong_family_for_check(mod) -> None:
    import copy

    matrix = copy.deepcopy(mod.load_matrix())
    matrix["families"][0]["pass_case"]["checks"][0]["check_id"] = "exo-dkim-enabled"
    problems = mod.validate_matrix(matrix)
    assert any("belongs to another family" in p for p in problems)


def test_redact_command_cleans_sample(mod) -> None:
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        code = mod.main(["redact"])
    assert code == 0
    assert mod.find_leaks(buf.getvalue()) == []
