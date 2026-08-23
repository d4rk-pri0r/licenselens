#!/usr/bin/env python3
"""Offline validator for the flagship check registry (catalog/flagships.yaml).

Enforces the §25 flagship quality gate fail-closed:

1. Every ``check_id`` in ``catalog/flagships.yaml`` exists in the check YAMLs,
   is marked ``flagship: true``, and carries all required metadata fields
   non-empty (security_intent, entitlement, evidence_source, assessment_type)
   plus the source-of-truth reference fields (source_url, source_type).
2. Every flagship check must have a non-empty ``references:`` list plus
   non-empty ``customer_title``, ``customer_summary``, ``expected_state``,
   ``remediation``, and ``required_capabilities``.
3. Every check marked ``flagship: true`` in a YAML is present in
   ``catalog/flagships.yaml`` (no orphan flagships).
4. No flagship has ``support_state`` 'proxy' or 'manual' per reference.json.

Exit code 1 with one violation per line when anything fails; 0 when clean.

Usage: python scripts/validate_flagship_meta.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Final

import yaml

from licenselens.engine.loader import load_checks

_REQUIRED_CATALOG_FIELDS: Final = (
    "security_intent",
    "entitlement",
    "evidence_source",
    "assessment_type",
    "source_url",
    "source_type",
)
_REQUIRED_CHECK_FIELDS: Final = (
    "customer_title",
    "customer_summary",
    "expected_state",
    "remediation",
    "required_capabilities",
)
_FORBIDDEN_SUPPORT_STATES: Final = frozenset({"proxy", "manual"})


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _load_reference_checks(root: Path) -> dict[str, dict]:
    path = root / "docs" / "reference" / "reference.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    checks = raw.get("checks") or []
    return {str(entry.get("id")): entry for entry in checks if isinstance(entry, dict)}


def validate_flagship_meta(
    catalog_path: Path | None = None,
    checks_root: Path | None = None,
    reference_path: Path | None = None,
) -> list[str]:
    """Return violation messages; an empty list means the flagship gate passes."""
    root = _repo_root()
    catalog_path = catalog_path or (root / "catalog" / "flagships.yaml")
    checks_root = checks_root or (root / "checks")
    reference_path = reference_path or (root / "docs" / "reference" / "reference.json")

    violations: list[str] = []
    catalog_raw = _load_yaml(catalog_path)
    entries = catalog_raw.get("flagships") or []
    if not isinstance(entries, list) or not entries:
        return ["flagships.yaml: missing or empty 'flagships' list"]

    catalog_by_id: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("check_id"):
            violations.append("flagships.yaml: flagship entry missing 'check_id'")
            continue
        check_id = str(entry["check_id"])
        if check_id in catalog_by_id:
            violations.append(f"flagships.yaml: duplicate flagship {check_id!r}")
        catalog_by_id[check_id] = entry

    checks = load_checks(checks_root)
    checks_by_id = {check.id: check for check in checks}
    reference_by_id = _load_reference_checks(root)

    for check_id, entry in sorted(catalog_by_id.items()):
        check = checks_by_id.get(check_id)
        if check is None:
            violations.append(f"unknown_flagship:{check_id}:not in checks")
            continue
        if not check.flagship:
            violations.append(f"not_marked_flagship:{check_id}")
        for field in _REQUIRED_CATALOG_FIELDS:
            value = entry.get(field)
            if not isinstance(value, str) or not value.strip():
                violations.append(f"missing_catalog_field:{check_id}:{field}")
        for field in _REQUIRED_CHECK_FIELDS:
            value = getattr(check, field)
            if not value:
                violations.append(f"missing_check_field:{check_id}:{field}")
        if not check.references:
            violations.append(f"missing_references:{check_id}")
        ref = reference_by_id.get(check_id)
        if ref is None:
            violations.append(f"missing_reference_entry:{check_id}")
        else:
            support_state = str(ref.get("support_state") or "")
            if support_state in _FORBIDDEN_SUPPORT_STATES:
                violations.append(f"forbidden_support_state:{check_id}:{support_state}")

    for check in checks:
        if check.flagship and check.id not in catalog_by_id:
            violations.append(f"orphan_flagship:{check.id}:marked in YAML but not in catalog")

    return violations


def main() -> int:
    violations = validate_flagship_meta()
    if violations:
        print("Flagship meta validation FAILED:")
        for message in violations:
            print(f"  - {message}")
        return 1
    catalog = _load_yaml(_repo_root() / "catalog" / "flagships.yaml")
    count = len(catalog.get("flagships") or [])
    print(f"Flagship meta validation OK: {count} flagships validated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
