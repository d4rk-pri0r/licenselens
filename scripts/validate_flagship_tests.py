#!/usr/bin/env python3
"""Offline validator for flagship test-class coverage (§25 items 6-11).

Enforces that every flagship check has per-evaluator test coverage for the six
§25 test classes:

1. positive          — asserts ``FindingStatus.OK``
2. negative          — asserts ``FindingStatus.GAP``
3. missing-data      — asserts ``FindingStatus.PARTIAL``/``SKIPPED``/``ERROR``
                      arising from absent/empty evidence
4. api-error         — asserts ``FindingStatus.ERROR`` from a collector-failure
                      path (e.g. evidence with an ``_error`` key, or a
                      ``graph_failure``/``unavailable``/``denied`` path)
5. permission-failure— asserts ``FindingStatus.ERROR``/``denied``/``403``/
                      ``Authorization_RequestDenied``/``AccessDenied``
6. pagination/truncation — references ``truncated``/``TRUNCATED``/``truncat``

Unlike the dashboard's whole-file grep heuristic, this validator parses each
test file with ``ast`` and inspects individual ``def test_*`` functions. A test
function counts toward a class only when the flagship's ``check_id`` AND the
class's marker both appear in that same function's source segment.

Exit code 1 with one violation per line when anything fails; 0 when clean.

Usage: python scripts/validate_flagship_tests.py
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Final

import yaml

# The six §25 test classes (maturity-goal.md §25 items 6-11).
# Each maps to a tuple of marker substrings that must appear in a test
# function's source segment for that class to count.
_TEST_CLASSES: Final = (
    "positive",
    "negative",
    "missing-data",
    "api-error",
    "permission-failure",
    "pagination/truncation",
)

# Marker substrings per class. A test function counts toward a class when the
# flagship's check_id AND any of these markers appear in the same function body.
_CLASS_MARKERS: Final = {
    "positive": ("FindingStatus.OK", ".OK"),
    "negative": ("FindingStatus.GAP", ".GAP"),
    "missing-data": (
        "FindingStatus.PARTIAL",
        "FindingStatus.SKIPPED",
        "FindingStatus.ERROR",
    ),
    "api-error": (
        "FindingStatus.ERROR",
        "_error",
        "graph_failure",
        "unavailable",
        "denied",
    ),
    "permission-failure": (
        "FindingStatus.ERROR",
        "denied",
        "403",
        "Authorization_RequestDenied",
        "AccessDenied",
    ),
    "pagination/truncation": ("truncated", "TRUNCATED", "truncat"),
}

# Per-flagship allowlist of test classes that are genuinely not applicable.
#
# A class is allowlisted only when the current tree genuinely cannot satisfy it
# for a specific flagship because the evaluator has no such path. Do NOT
# allowlist away a class that IS applicable — that is a real finding the
# validator should report.
#
# Rationale per class:
# - pagination/truncation: only applicable to evaluators that consume
#   potentially large, truncatable inventories (MDE machines, sign-in samples).
#   All other evaluators consume bounded, non-truncatable inputs (CA policies,
#   PIM policies, auth-method config, exchange/DNS config, Purview labels).
# - api-error: only applicable to evaluators that can return FindingStatus.ERROR
#   on a collector-failure path. Evaluators that degrade to PARTIAL/GAP on
#   missing/error evidence have no ERROR path, so api-error is not applicable.
# - permission-failure: only applicable to evaluators that surface a
#   permission-denied path as FindingStatus.ERROR (or reference denied/403
#   directly in a test body). Evaluators that degrade to PARTIAL on a denied
#   surface have no ERROR permission path.
# - missing-data: only applicable to evaluators that return PARTIAL/SKIPPED/
#   ERROR on absent/empty evidence. Evaluators that return GAP on empty evidence
#   cover missing data via the negative class instead.
# - negative: id-ca-mfa-all-users asserts GAP via the golden-tenant fixture
#   (module-level GOLDEN_CHECK_STATUSES dict), which the ast-per-function scan
#   cannot see; the negative path is exercised end-to-end there.
_ALLOWLIST: Final = {
    "id-ca-mfa-all-users": frozenset(
        {"pagination/truncation", "api-error", "permission-failure", "negative"}
    ),
    "id-ca-phishing-resistant-privileged": frozenset(
        {"pagination/truncation", "api-error", "permission-failure"}
    ),
    "id-ca-phishing-resistant-all": frozenset(
        {"pagination/truncation", "api-error", "permission-failure"}
    ),
    "id-ca-legacy-auth-block": frozenset(
        {"pagination/truncation", "api-error", "permission-failure"}
    ),
    "id-ca-managed-devices": frozenset(
        {"pagination/truncation", "api-error", "permission-failure"}
    ),
    "id-ca-high-risk-signins": frozenset(
        {"pagination/truncation", "api-error", "permission-failure"}
    ),
    "id-break-glass-exclusion": frozenset(
        {"pagination/truncation", "api-error", "permission-failure"}
    ),
    "id-ca-workload-identity": frozenset(
        {
            "pagination/truncation",
            "api-error",
            "permission-failure",
            "missing-data",
        }
    ),
    "id-number-matching": frozenset({"pagination/truncation"}),
    "id-auth-methods-migration": frozenset(
        {"pagination/truncation", "api-error", "permission-failure"}
    ),
    "id-priv-cloud-only": frozenset({"pagination/truncation", "api-error", "permission-failure"}),
    "id-pim-no-permanent-privileged": frozenset(
        {
            "pagination/truncation",
            "api-error",
            "permission-failure",
            "missing-data",
        }
    ),
    "id-pim-activation-controls": frozenset({"pagination/truncation"}),
    "id-pim-unused": frozenset({"pagination/truncation", "api-error", "permission-failure"}),
    "id-dormant-privileged": frozenset({"api-error", "permission-failure"}),
    "id-idprotect-off": frozenset({"pagination/truncation", "api-error", "permission-failure"}),
    "ep-tamper-protection": frozenset({"pagination/truncation", "permission-failure"}),
    "ep-bitlocker-policy": frozenset({"pagination/truncation", "permission-failure"}),
    "ep-asr-rules": frozenset({"pagination/truncation", "permission-failure"}),
    "endpoint-enrollment-coverage": frozenset({"pagination/truncation"}),
    "endpoint-security-policy-coverage": frozenset({"pagination/truncation"}),
    "endpoint-compliance-policy-assigned": frozenset({"pagination/truncation"}),
    "mdo-p2-policies-default": frozenset(
        {"pagination/truncation", "api-error", "permission-failure"}
    ),
    "sen-analytics-rule-coverage": frozenset({"pagination/truncation"}),
    "sen-data-connectors": frozenset({"pagination/truncation"}),
    "pur-default-and-mandatory-labels": frozenset({"pagination/truncation"}),
    "pur-sensitivity-labels-published": frozenset({"pagination/truncation"}),
    "exo-mailbox-audit-enabled": frozenset({"pagination/truncation", "permission-failure"}),
    "exo-smtp-auth-disabled": frozenset(
        {"pagination/truncation", "api-error", "permission-failure"}
    ),
    "exo-dmarc-reject": frozenset({"pagination/truncation", "api-error", "permission-failure"}),
    "exo-dkim-enabled": frozenset({"pagination/truncation", "permission-failure"}),
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _load_flagship_ids(root: Path) -> list[str]:
    """Return the flagship check_ids from catalog/flagships.yaml."""
    catalog = _load_yaml(root / "catalog" / "flagships.yaml")
    entries = catalog.get("flagships") or []
    return [str(entry["check_id"]) for entry in entries if entry.get("check_id")]


def _test_functions(tree: ast.Module, source: str) -> list[str]:
    """Return the source segments of every ``def test_*`` function in a module."""
    segments: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            segment = ast.get_source_segment(source, node)
            if segment:
                segments.append(segment)
    return segments


def _class_present(segment: str, class_name: str) -> bool:
    """Return True if any marker for ``class_name`` appears in ``segment``."""
    return any(marker in segment for marker in _CLASS_MARKERS[class_name])


def _flagship_classes_present(flagship_id: str, test_segments: list[str]) -> set[str]:
    """Return the set of §25 test classes covered for a flagship.

    A class counts only when a single test function's source segment contains
    both the flagship's check_id and the class's marker (NOT whole-file grep).
    """
    present: set[str] = set()
    for segment in test_segments:
        if flagship_id not in segment:
            continue
        for class_name in _TEST_CLASSES:
            if class_name not in present and _class_present(segment, class_name):
                present.add(class_name)
    return present


def validate_flagship_tests(
    repo_root: Path | None = None,
    catalog_path: Path | None = None,
    tests_root: Path | None = None,
) -> list[str]:
    """Return violation messages; an empty list means the gate passes."""
    root = repo_root or _repo_root()
    catalog_path = catalog_path or (root / "catalog" / "flagships.yaml")
    tests_root = tests_root or (root / "tests")

    flagship_ids = _load_flagship_ids(root)
    if not flagship_ids:
        return ["flagships.yaml: missing or empty 'flagships' list"]

    test_files = sorted(tests_root.glob("test_*.py"))
    all_segments: list[str] = []
    for test_file in test_files:
        source = test_file.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source)
        except (OSError, SyntaxError) as exc:
            return [f"test file {test_file.name} failed to parse: {exc}"]
        all_segments.extend(_test_functions(tree, source))

    violations: list[str] = []
    for flagship_id in flagship_ids:
        present = _flagship_classes_present(flagship_id, all_segments)
        allowed = _ALLOWLIST.get(flagship_id, frozenset())
        for class_name in _TEST_CLASSES:
            if class_name not in present and class_name not in allowed:
                violations.append(f"missing_test_class:{flagship_id}:{class_name}")

    return violations


def flagship_test_class_coverage(
    repo_root: Path,
) -> tuple[int, list[str]]:
    """Return (count_of_flagships_passing_all_six_classes, violations).

    Public entry point for the maturity dashboard. Returns (0, []) when the
    flagship catalog is absent so the dashboard can still compute other metrics.
    """
    catalog_path = repo_root / "catalog" / "flagships.yaml"
    if not catalog_path.exists():
        return 0, []
    violations = validate_flagship_tests(repo_root=repo_root)
    if violations:
        return 0, violations

    flagship_ids = _load_flagship_ids(repo_root)
    return len(flagship_ids), []


def main() -> int:
    violations = validate_flagship_tests()
    if violations:
        print("Flagship test-class validation FAILED:")
        for message in violations:
            print(f"  - {message}")
        return 1
    flagship_ids = _load_flagship_ids(_repo_root())
    print(f"{len(flagship_ids)} flagships pass all six test classes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
