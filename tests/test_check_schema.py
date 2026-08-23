"""Schema guard for the optional `mappings:` block on identity+endpoint check YAMLs.

Every check under ``checks/identity/`` and ``checks/endpoint/`` must carry a
well-formed ``mappings`` block with non-empty ``nist`` (NIST SP 800-53 rev5)
and ``mitre`` (MITRE ATT&CK) ID lists. This test is the validator guard that
rejects malformed mapping values.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHECK_DIRS = (ROOT / "checks" / "identity", ROOT / "checks" / "endpoint")

NIST_PATTERN = re.compile(r"^[A-Z]+-[0-9]+(\.[0-9]+)?$")
MITRE_PATTERN = re.compile(r"^T[0-9]{4}(\.\d+)?$")


def _check_yamls() -> list[Path]:
    return sorted(path for directory in CHECK_DIRS for path in directory.glob("*.yaml"))


def _validate_mappings(data: dict) -> list[str]:
    """Return a list of validation errors for a check's mappings block."""
    errors: list[str] = []
    mappings = data.get("mappings")
    if not isinstance(mappings, dict):
        return ["missing mappings block"]
    for key, pattern in (("nist", NIST_PATTERN), ("mitre", MITRE_PATTERN)):
        values = mappings.get(key)
        if not isinstance(values, list) or not values:
            errors.append(f"mappings.{key} must be a non-empty list")
            continue
        for value in values:
            if not isinstance(value, str) or pattern.fullmatch(value) is None:
                errors.append(f"mappings.{key} has invalid ID {value!r}")
    return errors


def test_all_identity_and_endpoint_checks_have_valid_mappings():
    """Every identity+endpoint check YAML has a well-formed mappings block."""
    yamls = _check_yamls()
    assert len(yamls) == 65, f"expected 65 identity+endpoint checks, got {len(yamls)}"
    for path in yamls:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        errors = _validate_mappings(data)
        assert not errors, f"{path.name}: {errors}"


def test_malformed_mapping_value_is_rejected(tmp_path: Path):
    """A fixture YAML with a malformed nist value is rejected by the validator."""
    fixture = tmp_path / "bad-check.yaml"
    fixture.write_text(
        "id: bad-check\n"
        "title: Bad\n"
        "workload: identity\n"
        "mappings:\n"
        '  nist: ["not-a-control"]\n'
        "  mitre: [\"T1078\"]\n",
        encoding="utf-8",
    )
    data = yaml.safe_load(fixture.read_text(encoding="utf-8"))
    errors = _validate_mappings(data)
    assert errors, "malformed nist value should be rejected"
    assert any("nist" in error for error in errors)


def test_empty_mapping_list_is_rejected(tmp_path: Path):
    """An empty nist/mitre list is rejected by the validator."""
    fixture = tmp_path / "empty-check.yaml"
    fixture.write_text(
        "id: empty-check\n"
        "title: Empty\n"
        "workload: identity\n"
        "mappings:\n"
        "  nist: []\n"
        "  mitre: [\"T1078\"]\n",
        encoding="utf-8",
    )
    data = yaml.safe_load(fixture.read_text(encoding="utf-8"))
    errors = _validate_mappings(data)
    assert errors, "empty nist list should be rejected"
    assert any("nist" in error for error in errors)
