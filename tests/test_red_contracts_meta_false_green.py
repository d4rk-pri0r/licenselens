"""Meta-guard: reject a false-green weakening of the RED legacy-map contract."""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MAP_PATH = ROOT / "src" / "licenselens" / "engine" / "_registry_check_map.py"


def reject_false_green(*, defect_present: bool, strict_contract_passed: bool) -> None:
    """Fail closed when a contract would pass while its audit defect remains."""
    if defect_present and strict_contract_passed:
        raise AssertionError(
            "false-green: RED contract passed while the audit defect is still present"
        )


def test_meta_guard_rejects_weakened_legacy_map_contract() -> None:
    """Temporarily weakened assertion would pass; sentinel must catch false-green."""
    defect_present = MAP_PATH.exists()
    strict_passed = not MAP_PATH.exists()

    # Proper RED state today: defect present, strict contract not passed.
    reject_false_green(
        defect_present=defect_present,
        strict_contract_passed=strict_passed,
    )
    assert defect_present, "legacy map defect fixture missing; cannot prove false-green guard"

    # Weakened tautology (always true) — the false-green stand-in.
    weakened_passed = MAP_PATH.exists() or not MAP_PATH.exists()
    assert weakened_passed is True

    with pytest.raises(AssertionError, match="false-green"):
        reject_false_green(
            defect_present=True,
            strict_contract_passed=weakened_passed,
        )
