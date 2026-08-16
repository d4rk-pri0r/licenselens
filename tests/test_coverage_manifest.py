from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate_coverage_manifest.py"
MANIFEST_PATH = ROOT / "catalog" / "coverage" / "scuba-2026-08.yaml"
type PolicyRow = dict[str, str | list[str]]
type ManifestYaml = dict[str, int | str | list[PolicyRow]]


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_coverage_manifest", VALIDATOR_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["validate_coverage_manifest"] = module
    spec.loader.exec_module(module)
    return module


def _manifest_data() -> ManifestYaml:
    raw = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return raw


def _write_manifest(path: Path, policies: list[PolicyRow]) -> None:
    data = _manifest_data()
    path.write_text(
        yaml.safe_dump(
            {
                "manifest_version": 1,
                "source": "SCuBA markdown baselines",
                "policies": policies,
                "untracked_policies": data.get("untracked_policies") or [],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def test_real_manifest_matches_pinned_policy_inventory() -> None:
    # Given the pinned SCuBA manifest shipped with the repository.
    validator = _load_validator()

    # When the offline validator reads the real manifest.
    result = validator.validate_manifest(MANIFEST_PATH)

    # Then every pinned markdown heading is represented exactly once, either as
    # a mapped policy row or as an explicitly untracked row with a rationale.
    assert result.policy_count == 129
    assert result.untracked_count == 4
    assert result.baseline_total == 133
    assert result.product_counts == {
        "aad": 34,
        "defender": 19,
        "exo": 12,
        "powerbi": 8,
        "powerplatform": 9,
        "securitysuite": 25,
        "sharepoint": 8,
        "teams": 14,
    }
    assert result.sha256


def test_real_manifest_keeps_securitysuite_heading_and_excludes_rego_only_policy() -> None:
    # Given the real manifest as structured YAML data.
    data = _manifest_data()
    policies = data["policies"]
    policy_ids = {policy["policy_id"] for policy in policies}

    # When the known upstream edge cases are checked.
    securitysuite = next(
        policy for policy in policies if policy["policy_id"] == "MS.SECURITYSUITE.7.2v1"
    )
    orphan = next(
        policy for policy in policies if policy["policy_id"] == "MS.SECURITYSUITE.15.2v1"
    )

    # Then the heading wins over hidden-comment typos and Rego-only IDs stay excluded,
    # while the orphaned 15.2 row is disposed against the real-time scan check.
    assert securitysuite["product"] == "securitysuite"
    assert orphan["product"] == "securitysuite"
    assert orphan["disposition"] == "implemented_direct"
    assert "mdo-safe-links-real-time-scan" in orphan["local_check_ids"]
    assert "MS.POWERPLATFORM.2.3v1" not in policy_ids
    assert sum(1 for policy in policies if policy["product"] == "defender") == 19
    untracked = data.get("untracked_policies") or []
    assert {entry["policy_id"] for entry in untracked} == {
        "MS.EXO.16.1v1",
        "MS.TEAMS.5.1v1",
        "MS.TEAMS.5.2v1",
        "MS.TEAMS.5.3v1",
    }


def test_validator_rejects_duplicate_policy(tmp_path: Path) -> None:
    # Given a manifest fixture with one duplicated policy row.
    data = _manifest_data()
    policies = [*data["policies"], data["policies"][0]]
    fixture = tmp_path / "duplicate.yaml"
    _write_manifest(fixture, policies)
    validator = _load_validator()

    # When validation runs.
    result = validator.validate_manifest(fixture)

    # Then the duplicate policy is a typed failure.
    assert "duplicate_policy" in result.error_codes


def test_validator_rejects_unpinned_source_url(tmp_path: Path) -> None:
    # Given a manifest fixture whose source URL points at a mutable branch.
    data = _manifest_data()
    policies = [dict(policy) for policy in data["policies"]]
    policies[0]["source_url"] = policies[0]["source_url"].replace(
        validator_commit(),
        "main",
    )
    fixture = tmp_path / "unpinned.yaml"
    _write_manifest(fixture, policies)
    validator = _load_validator()

    # When validation runs.
    result = validator.validate_manifest(fixture)

    # Then mutable upstream references are rejected.
    assert "unpinned_source_url" in result.error_codes


def test_validator_rejects_protected_prose_and_rego_payload(tmp_path: Path) -> None:
    # Given manifest rows containing copied-content fields and Rego-like payloads.
    data = _manifest_data()
    policies = [dict(policy) for policy in data["policies"]]
    policies[0]["implementation"] = "copied implementation text is not allowed"
    policies[1]["rationale"] = 'some x { input.PolicyId == "MS.AAD.1.1v1" }'
    fixture = tmp_path / "copied.yaml"
    _write_manifest(fixture, policies)
    validator = _load_validator()

    # When validation runs.
    result = validator.validate_manifest(fixture)

    # Then both protected prose fields and Rego signatures are rejected.
    assert "forbidden_field" in result.error_codes
    assert "rego_signature" in result.error_codes


def test_validator_cli_fails_for_invalid_manifest(tmp_path: Path) -> None:
    # Given a manifest fixture that uses an unsupported product family.
    data = _manifest_data()
    policies = [dict(policy) for policy in data["policies"]]
    policies[0]["product"] = "purview"
    fixture = tmp_path / "bad-product.yaml"
    _write_manifest(fixture, policies)

    # When the validator is used through its command-line surface.
    completed = subprocess.run(
        [sys.executable, str(VALIDATOR_PATH), str(fixture)],
        check=False,
        capture_output=True,
        text=True,
    )

    # Then it exits non-zero and prints the typed failure code.
    assert completed.returncode == 1
    assert "invalid_product" in completed.stdout


def test_validator_enforces_total_baseline_of_133(tmp_path: Path) -> None:
    # Given a manifest fixture whose untracked list drops one baseline row.
    data = _manifest_data()
    policies = [dict(policy) for policy in data["policies"]]
    fixture = tmp_path / "short-baseline.yaml"
    fixture.write_text(
        yaml.safe_dump(
            {
                "manifest_version": 1,
                "source": "SCuBA markdown baselines",
                "policies": policies,
                "untracked_policies": (data.get("untracked_policies") or [])[1:],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    validator = _load_validator()

    # When validation runs.
    result = validator.validate_manifest(fixture)

    # Then the 133-row baseline total is enforced and the dropped row is reported.
    assert result.baseline_total == 132
    assert "baseline_total_mismatch" in result.error_codes
    assert "missing_policy" in result.error_codes
    assert any(error.startswith("missing_policy:exo:MS.EXO.16.1v1") for error in result.errors)


def test_validator_rejects_untracked_row_that_is_already_mapped(tmp_path: Path) -> None:
    # Given a manifest fixture whose untracked list duplicates a mapped policy row.
    data = _manifest_data()
    policies = [dict(policy) for policy in data["policies"]]
    fixture = tmp_path / "double-counted.yaml"
    fixture.write_text(
        yaml.safe_dump(
            {
                "manifest_version": 1,
                "source": "SCuBA markdown baselines",
                "policies": policies,
                "untracked_policies": [
                    {
                        "product": "aad",
                        "policy_id": "MS.AAD.1.1v1",
                        "source_url": (
                            "https://github.com/cisagov/ScubaGear/blob/"
                            "1bc029182f9a11c420d0ea2bb3c7b12d2e687f5e/"
                            "PowerShell/ScubaGear/baselines/aad.md#L79"
                        ),
                        "rationale": "Duplicate of a mapped row.",
                    },
                    *(data.get("untracked_policies") or []),
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    validator = _load_validator()

    # When validation runs.
    result = validator.validate_manifest(fixture)

    # Then double-counting a mapped row is a typed failure.
    assert "untracked_already_mapped" in result.error_codes


def validator_commit() -> str:
    return "1bc029182f9a11c420d0ea2bb3c7b12d2e687f5e"
