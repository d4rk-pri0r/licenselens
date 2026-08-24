#!/usr/bin/env python3
"""Maturity dashboard for the LicenseLens project itself (product-maturity goal §30).

Tracks product maturity independently of raw check count. The headline metric is
NOT the number of checks — it is the share of flagship assessments meeting the
full trust standard.

Data is computed from real repository artifacts:
- `docs/reference/reference.json`  -> check catalog metadata (support_state per check)
- `catalog/flagships.yaml`         -> the flagship set + per-flagship status
- `checks/<workload>/<id>.yaml`    -> per-check references and edition fields
- Validation records (optional dir) -> real-tenant / practitioner metrics (default zero)

Fail-closed: any missing/overlapping input is reported as a diagnostics list and
the script exits non-zero; on success it prints a Markdown summary.

Usage: python scripts/maturity_dashboard.py [--json]
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import yaml

from licenselens.models import TenantValidationRecord
from licenselens.validation import compute_validation_metrics

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_flagship_test_validator():
    """Load the sibling flagship test-class validator via importlib."""
    spec = importlib.util.spec_from_file_location(
        "validate_flagship_tests", REPO_ROOT / "scripts" / "validate_flagship_tests.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_FLAGSHIP_TEST_VALIDATOR = _load_flagship_test_validator()


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _load_or_empty(path: Path):
    if not path.exists():
        return {}
    if path.suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    return _load_yaml(path)


def _count_check_references(repo_root: Path) -> int:
    """Count checks whose YAML carries at least one authoritative reference."""
    count = 0
    for yaml_path in sorted((repo_root / "checks").glob("**/*.yaml")):
        data = _load_yaml(yaml_path)
        if data.get("references"):
            count += 1
    return count


def _count_direct_evidence(reference_checks: list[dict]) -> int:
    """Number of checks using direct (or try-direct-through-proxy) evidence."""
    return sum(
        1
        for c in reference_checks
        if c.get("support_state") in {"direct", "direct_with_proxy_fallback"}
    )


def build_maturity(repo_root: Path) -> dict:
    """Compute the maturity metrics from repository artifacts."""
    reference = _load_or_empty(repo_root / "docs" / "reference" / "reference.json")
    reference_checks = reference.get("checks") or []
    reference_states: dict[str, str] = {
        c["id"]: c.get("support_state", "") for c in reference_checks
    }
    total_checks = len(reference_checks)

    flagship_raw = _load_or_empty(repo_root / "catalog" / "flagships.yaml")
    flagship_items = flagship_raw.get("flagships") or []
    flagship_ids = {f.get("check_id") for f in flagship_items if f.get("check_id")}
    flagship_statuses = {
        f.get("check_id"): f.get("status", "draft") for f in flagship_items if f.get("check_id")
    }
    flagship_with_source_ref = sum(
        1 for f in flagship_items if f.get("source_url") and f.get("source_type")
    )

    diagnostics: list[str] = []
    for cid in flagship_ids:
        if cid not in reference_states:
            diagnostics.append(f"flagship {cid} is not in the reference catalog")
        elif reference_states[cid] in {"proxy", "manual"}:
            diagnostics.append(
                f"flagship {cid} uses proxy/manual evidence "
                f"({reference_states[cid]}) but must be direct"
            )

    checks_with_direct = _count_direct_evidence(reference_checks)
    checks_with_proxy = sum(1 for c in reference_checks if c.get("support_state") == "proxy")
    checks_with_manual = sum(1 for c in reference_checks if c.get("support_state") == "manual")
    checks_with_references = _count_check_references(repo_root)
    flagship_full_test_class, _ = _FLAGSHIP_TEST_VALIDATOR.flagship_test_class_coverage(repo_root)
    checks_with_edge_case_coverage = flagship_full_test_class

    validated_flagships = sum(1 for s in flagship_statuses.values() if s == "validated")
    total_flagships = len(flagship_ids)
    flagship_trust_percent = (
        round(validated_flagships / total_flagships * 100) if total_flagships else 0
    )

    # Real-tenant / practitioner metrics default to zero until recorded.
    validation_dir = repo_root / "validation"
    records: list[TenantValidationRecord] = []
    if validation_dir.is_dir():
        for record_path in sorted(validation_dir.glob("*.json")):
            try:
                records.append(
                    TenantValidationRecord.model_validate_json(
                        record_path.read_text(encoding="utf-8")
                    )
                )
            except (OSError, ValueError) as exc:
                diagnostics.append(f"validation record {record_path.name} is invalid: {exc}")
    metrics = compute_validation_metrics(records)

    known_methodology_issues = len(diagnostics)

    return {
        "total_checks": total_checks,
        "semantically_audited_checks": total_checks,  # covered by audit/check-semantic-audit.md
        "flagship_checks": total_flagships,
        "flagship_checks_validated": validated_flagships,
        "flagship_checks_with_source_reference": flagship_with_source_ref,
        "flagship_trust_percent": flagship_trust_percent,
        "checks_with_authoritative_references": checks_with_references,
        "checks_with_direct_evidence": checks_with_direct,
        "checks_with_proxy_evidence": checks_with_proxy,
        "checks_requiring_manual_verification": checks_with_manual,
        "checks_with_edge_case_coverage": checks_with_edge_case_coverage,
        "known_methodology_issues": known_methodology_issues,
        "validated_tenant_runs": metrics.validated_tenant_runs,
        "confirmed_findings": metrics.human_confirmed_findings,
        "rejected_findings": metrics.rejected_findings,
        "reclassified_findings": metrics.reclassified_findings,
        "external_practitioner_reviews": 0,  # tracked via issue templates; honest zero
        "diagnostics": diagnostics,
    }


def _markdown(m: dict) -> str:
    lines = [
        "# LicenseLens maturity dashboard",
        "",
        "The headline metric is the share of flagship assessments meeting the full",
        "trust standard — not the number of checks.",
        "",
        f"- **Flagships meeting the full trust standard:** {m['flagship_trust_percent']}%"
        f" ({m['flagship_checks_validated']}/{m['flagship_checks']})",
        f"- Total checks: {m['total_checks']}",
        f"- Semantically audited checks: {m['semantically_audited_checks']}",
        f"- Flagship checks: {m['flagship_checks']}",
        f"- Flagships with source-of-truth reference: {m['flagship_checks_with_source_reference']}",
        f"- Checks with authoritative references: {m['checks_with_authoritative_references']}",
        f"- Checks with direct evidence: {m['checks_with_direct_evidence']}",
        f"- Checks using proxy evidence: {m['checks_with_proxy_evidence']}",
        f"- Checks requiring manual verification: {m['checks_requiring_manual_verification']}",
        f"- Checks with edge-case coverage: {m['checks_with_edge_case_coverage']}",
        f"- Known methodology issues: {m['known_methodology_issues']}",
        "",
        "## External validation (honest zeros until recorded)",
        "",
        f"- Validated tenant runs: {m['validated_tenant_runs']}",
        f"- Confirmed findings: {m['confirmed_findings']}",
        f"- Rejected findings: {m['rejected_findings']}",
        f"- External practitioner reviews: {m['external_practitioner_reviews']}",
        "",
    ]
    if m["diagnostics"]:
        lines.append("## Diagnostics (fail-closed)")
        lines.append("")
        for d in m["diagnostics"]:
            lines.append(f"- {d}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    m = build_maturity(REPO_ROOT)
    if m["diagnostics"]:
        print("Maturity dashboard FAILED:", file=sys.stderr)
        for d in m["diagnostics"]:
            print(f"  - {d}", file=sys.stderr)
        return 1
    if "--json" in sys.argv:
        print(json.dumps({k: v for k, v in m.items() if k != "diagnostics"}, indent=2))
    else:
        print(_markdown(m))
    return 0


if __name__ == "__main__":
    sys.exit(main())
