"""SCuBA coverage map: policy_id → local check ids.

Wraps the reference coverage loader so ingest and docs share one mapping.
"""

from __future__ import annotations

from pathlib import Path

from licenselens.catalog._reference_coverage import load_coverage_rows
from licenselens.engine.loader import load_checks
from licenselens.paths import catalog_dir

DEFAULT_COVERAGE_PATH = catalog_dir() / "coverage" / "scuba-2026-08.yaml"


def scuba_policy_map(path: Path | None = None) -> dict[str, tuple[str, ...]]:
    """Return policy_id → local_check_ids for rows that map to LicenseLens checks."""
    coverage_path = path or DEFAULT_COVERAGE_PATH
    check_ids = {check.id for check in load_checks()}
    rows, _errors = load_coverage_rows(coverage_path, check_ids)
    return {row.policy_id: row.local_check_ids for row in rows if row.local_check_ids}
