"""Maturity dashboard (§30) — self-metrics computed from real repository data.

The headline is the share of flagships meeting the trust standard, never the raw
check count, and external-validation numbers default to zero until recorded.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module() -> object:
    spec = importlib.util.spec_from_file_location(
        "maturity_dashboard", REPO_ROOT / "scripts" / "maturity_dashboard.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_headline_is_flagship_trust_percent_not_check_count() -> None:
    mod = _load_module()
    m = mod.build_maturity(REPO_ROOT)
    assert m["flagship_trust_percent"] == 0  # 0 validated yet
    assert m["total_checks"] >= m["flagship_checks"]
    assert m["diagnostics"] == []


def test_all_checks_have_direct_or_explicit_state() -> None:
    mod = _load_module()
    m = mod.build_maturity(REPO_ROOT)
    # direct + proxy + manual should account for all checks in the reference
    reference = json.loads((REPO_ROOT / "docs" / "reference" / "reference.json").read_text())
    states = {c["support_state"] for c in reference["checks"]}
    total = len(reference["checks"])
    assert states <= {"direct", "proxy", "manual", "direct_with_proxy_fallback"}
    assert m["total_checks"] == total


def test_flagship_count_matches_registry() -> None:
    mod = _load_module()
    m = mod.build_maturity(REPO_ROOT)
    import yaml

    raw = yaml.safe_load((REPO_ROOT / "catalog" / "flagships.yaml").read_text())
    assert m["flagship_checks"] == len(raw.get("flagships") or []) >= 25


def test_external_metrics_are_honest_zero_by_default(tmp_path: Path) -> None:
    mod = _load_module()
    # Empty validation dir -> zeros.
    m = mod.build_maturity(tmp_path)
    assert m["validated_tenant_runs"] == 0
    assert m["confirmed_findings"] == 0
    assert m["rejected_findings"] == 0
    assert m["external_practitioner_reviews"] == 0
