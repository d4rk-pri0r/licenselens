"""Tests for the flagship check registry and its §25 quality-gate validator."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "catalog" / "flagships.yaml"
VALIDATOR_PATH = ROOT / "scripts" / "validate_flagship_meta.py"


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_flagship_meta", VALIDATOR_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["validate_flagship_meta"] = module
    spec.loader.exec_module(module)
    return module


_VALIDATOR = _load_validator()
validate_flagship_meta = _VALIDATOR.validate_flagship_meta

EXPECTED_FLAGSHIP_IDS = {
    "id-ca-mfa-all-users",
    "id-ca-phishing-resistant-privileged",
    "id-ca-phishing-resistant-all",
    "id-ca-priv-gaps",
    "id-ca-legacy-auth-block",
    "id-ca-managed-devices",
    "id-ca-high-risk-signins",
    "id-break-glass-exclusion",
    "id-ca-workload-identity",
    "id-number-matching",
    "id-auth-methods-migration",
    "id-priv-cloud-only",
    "id-pim-no-permanent-privileged",
    "id-pim-activation-controls",
    "id-pim-unused",
    "id-dormant-privileged",
    "id-idprotect-off",
    "mde-onboard-gap",
    "ep-tamper-protection",
    "ep-bitlocker-policy",
    "ep-asr-rules",
    "endpoint-enrollment-coverage",
    "endpoint-security-policy-coverage",
    "endpoint-compliance-policy-assigned",
    "mdo-p2-policies-default",
    "sen-analytics-rule-coverage",
    "sen-data-connectors",
    "sen-telemetry-ingestion-coverage",
    "sen-rule-telemetry-parity",
    "pur-dlp-not-enforced",
    "pur-default-and-mandatory-labels",
    "pur-sensitivity-labels-published",
    "exo-mailbox-audit-enabled",
    "exo-smtp-auth-disabled",
    "exo-dmarc-reject",
    "exo-dkim-enabled",
}


def _catalog_ids() -> set[str]:
    data = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    return {str(entry["check_id"]) for entry in data["flagships"]}


def test_all_36_flagships_present_in_catalog():
    assert _catalog_ids() == EXPECTED_FLAGSHIP_IDS


def test_validator_passes_on_current_tree():
    violations = validate_flagship_meta()
    assert violations == []


def _write_check(tmp_path: Path, check_id: str, *, references: list[str]) -> Path:
    check_dir = tmp_path / "checks" / "identity"
    check_dir.mkdir(parents=True, exist_ok=True)
    path = check_dir / f"{check_id}.yaml"
    path.write_text(
        "id: {id}\n"
        "title: Title\n"
        "customer_title: Customer title\n"
        "customer_summary: Customer summary\n"
        "expected_state: Expected state\n"
        "remediation: Remediation\n"
        "required_capabilities: [conditional_access]\n"
        "impact: high\n"
        "effort: hours\n"
        "blast_radius: all_users\n"
        "pack: identity\n"
        "exposure_class: none\n"
        "references:\n"
        "{references}\n"
        "flagship: true\n"
        "flagship_security_intent: Intent\n"
        "enabled: true\n"
        "tier: activation\n".format(
            id=check_id,
            references="".join(f"  - {url}\n" for url in references),
        ),
        encoding="utf-8",
    )
    return path


def test_orphan_flagship_fails_validator(tmp_path: Path):
    """A check marked flagship in YAML but absent from the catalog is rejected."""
    _write_check(tmp_path, "orphan-check", references=["https://example.com"])
    violations = validate_flagship_meta(
        catalog_path=CATALOG_PATH,
        checks_root=tmp_path / "checks",
    )
    assert any("orphan_flagship" in violation for violation in violations)


def test_flagship_with_empty_reference_fails_validator(tmp_path: Path):
    """A flagship whose check has an empty references list is rejected."""
    _write_check(tmp_path, "id-ca-mfa-all-users", references=[])
    violations = validate_flagship_meta(
        catalog_path=CATALOG_PATH,
        checks_root=tmp_path / "checks",
    )
    assert any("missing_references" in violation for violation in violations)


def test_every_catalog_flagship_carries_source_of_truth_ref():
    """§12: every flagship entry must carry source_url and source_type."""
    catalog = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    entries = catalog.get("flagships") or []
    assert len(entries) == len(EXPECTED_FLAGSHIP_IDS)
    for entry in entries:
        assert entry.get("source_url"), f"{entry['check_id']} missing source_url"
        assert entry.get("source_type"), f"{entry['check_id']} missing source_type"


def test_flagship_without_source_url_fails_validator(tmp_path: Path):
    """A flagship catalog entry without source_url is rejected (§12)."""
    _write_check(tmp_path, "id-ca-mfa-all-users", references=["https://learn.microsoft.com/x"])
    stripped = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    for entry in stripped.get("flagships") or []:
        entry.pop("source_url", None)
    catalog_path = tmp_path / "flagships.yaml"
    catalog_path.write_text(yaml.safe_dump(stripped, sort_keys=False), encoding="utf-8")
    violations = validate_flagship_meta(
        catalog_path=catalog_path,
        checks_root=tmp_path / "checks",
    )
    assert any("missing_catalog_field" in v and "source_url" in v for v in violations)
