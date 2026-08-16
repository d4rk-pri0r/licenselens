from __future__ import annotations

import hashlib
import re
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import yaml

PINNED_COMMIT: Final = "1bc029182f9a11c420d0ea2bb3c7b12d2e687f5e"
# Total baseline rows across all eight product baselines (aad.md, defender.md,
# exo.md, powerbi.md, powerplatform.md, securitysuite.md, sharepoint.md,
# teams.md): the 133 rows at the pinned commit plus the two rows
# (MS.SHAREPOINT.4.1v1, MS.TEAMS.3.1v1) that the newer baseline refresh added
# after the pin and that LicenseLens now tracks directly. Every row must be
# either a manifest policy row or an explicitly untracked row with a rationale.
BASELINE_TOTAL: Final = 135
ALLOWED_FIELDS: Final = frozenset(
    {
        "product",
        "product_name",
        "policy_id",
        "policy_version",
        "criticality",
        "check_type",
        "source_url",
        "pinned_commit",
        "local_check_ids",
        "disposition",
        "rationale",
    }
)
UNTRACKED_ALLOWED_FIELDS: Final = frozenset({"product", "policy_id", "source_url", "rationale"})
FORBIDDEN_FIELDS: Final = frozenset(
    {"name", "implementation", "resources", "recommendation", "long_rationale"}
)
DISPOSITIONS: Final = frozenset(
    {"implemented_direct", "implemented_proxy", "manual", "unsupported", "not_applicable"}
)
PRODUCT_PATHS: Final = {
    "aad": "PowerShell/ScubaGear/baselines/aad.md",
    "defender": "PowerShell/ScubaGear/baselines/defender.md",
    "securitysuite": "PowerShell/ScubaGear/baselines/securitysuite.md",
    "exo": "PowerShell/ScubaGear/baselines/exo.md",
    "sharepoint": "PowerShell/ScubaGear/baselines/sharepoint.md",
    "teams": "PowerShell/ScubaGear/baselines/teams.md",
    "powerplatform": "PowerShell/ScubaGear/baselines/powerplatform.md",
    "powerbi": "PowerShell/ScubaGear/baselines/powerbi.md",
}
EXPECTED_POLICY_TEXT: Final = {
    "aad": (
        "MS.AAD.1.1v1 MS.AAD.2.1v1 MS.AAD.2.2v1 "
        "MS.AAD.2.3v1 MS.AAD.3.1v1 MS.AAD.3.2v2 "
        "MS.AAD.3.3v2 MS.AAD.3.4v1 MS.AAD.3.5v2 "
        "MS.AAD.3.6v1 MS.AAD.3.7v1 MS.AAD.3.8v1 "
        "MS.AAD.3.9v1 MS.AAD.4.1v1 MS.AAD.5.1v1 "
        "MS.AAD.5.2v1 MS.AAD.5.3v1 MS.AAD.5.5v1 "
        "MS.AAD.5.6v1 MS.AAD.5.7v1 MS.AAD.6.1v1 "
        "MS.AAD.7.1v1 MS.AAD.7.2v1 MS.AAD.7.3v1 "
        "MS.AAD.7.4v1 MS.AAD.7.5v1 MS.AAD.7.6v1 "
        "MS.AAD.7.7v1 MS.AAD.7.8v1 MS.AAD.7.9v1 "
        "MS.AAD.8.1v1 MS.AAD.8.2v1 MS.AAD.8.3v1 "
        "MS.AAD.9.1v1"
    ),
    "securitysuite": (
        "MS.SECURITYSUITE.1.1v1 MS.SECURITYSUITE.1.2v1 MS.SECURITYSUITE.1.3v1 "
        "MS.SECURITYSUITE.1.4v1 MS.SECURITYSUITE.2.1v1 MS.SECURITYSUITE.2.2v1 "
        "MS.SECURITYSUITE.2.3v1 MS.SECURITYSUITE.2.4v1 MS.SECURITYSUITE.3.1v1 "
        "MS.SECURITYSUITE.3.2v1 MS.SECURITYSUITE.3.3v1 MS.SECURITYSUITE.3.4v1 "
        "MS.SECURITYSUITE.3.5v1 MS.SECURITYSUITE.4.1v1 MS.SECURITYSUITE.4.2v1 "
        "MS.SECURITYSUITE.5.1v1 MS.SECURITYSUITE.5.2v1 MS.SECURITYSUITE.6.1v1 "
        "MS.SECURITYSUITE.6.2v1 MS.SECURITYSUITE.7.1v1 MS.SECURITYSUITE.7.2v1 "
        "MS.SECURITYSUITE.7.3v1 MS.SECURITYSUITE.8.1v1 MS.SECURITYSUITE.8.2v1 "
        "MS.SECURITYSUITE.15.2v1"
    ),
    "defender": (
        "MS.DEFENDER.1.1v1 MS.DEFENDER.1.2v1 MS.DEFENDER.1.3v1 "
        "MS.DEFENDER.1.4v1 MS.DEFENDER.1.5v1 MS.DEFENDER.2.1v1 "
        "MS.DEFENDER.2.2v1 MS.DEFENDER.2.3v1 MS.DEFENDER.3.1v1 "
        "MS.DEFENDER.4.1v2 MS.DEFENDER.4.2v1 MS.DEFENDER.4.3v1 "
        "MS.DEFENDER.4.4v1 MS.DEFENDER.4.5v1 MS.DEFENDER.4.6v1 "
        "MS.DEFENDER.5.1v1 MS.DEFENDER.5.2v1 MS.DEFENDER.6.1v1 "
        "MS.DEFENDER.6.3v1"
    ),
    "exo": (
        "MS.EXO.1.1v2 MS.EXO.2.2v3 MS.EXO.3.1v1 "
        "MS.EXO.4.1v1 MS.EXO.4.2v1 MS.EXO.4.3v1 "
        "MS.EXO.4.4v1 MS.EXO.5.1v1 MS.EXO.6.1v1 "
        "MS.EXO.6.2v1 MS.EXO.7.1v1 MS.EXO.13.1v1 "
        "MS.EXO.16.1v1"
    ),
    "sharepoint": (
        "MS.SHAREPOINT.1.1v1 MS.SHAREPOINT.1.2v1 MS.SHAREPOINT.1.3v1 "
        "MS.SHAREPOINT.2.1v1 MS.SHAREPOINT.2.2v1 MS.SHAREPOINT.3.1v1 "
        "MS.SHAREPOINT.3.2v1 MS.SHAREPOINT.3.3v2 MS.SHAREPOINT.4.1v1"
    ),
    "teams": (
        "MS.TEAMS.1.1v1 MS.TEAMS.1.2v2 MS.TEAMS.1.3v1 "
        "MS.TEAMS.1.4v1 MS.TEAMS.1.5v1 MS.TEAMS.1.6v1 "
        "MS.TEAMS.1.7v2 MS.TEAMS.2.1v2 MS.TEAMS.2.2v2 "
        "MS.TEAMS.2.3v2 MS.TEAMS.3.1v1 MS.TEAMS.4.1v1 "
        "MS.TEAMS.5.1v1 MS.TEAMS.5.1v2 MS.TEAMS.5.2v1 "
        "MS.TEAMS.5.2v2 MS.TEAMS.5.3v1 MS.TEAMS.5.3v2"
    ),
    "powerplatform": (
        "MS.POWERPLATFORM.1.1v1 MS.POWERPLATFORM.1.2v1 MS.POWERPLATFORM.2.1v1 "
        "MS.POWERPLATFORM.2.2v1 MS.POWERPLATFORM.3.1v1 MS.POWERPLATFORM.3.2v1 "
        "MS.POWERPLATFORM.4.1v1 MS.POWERPLATFORM.5.1v1 MS.POWERPLATFORM.6.1v1"
    ),
    "powerbi": (
        "MS.POWERBI.1.1v1 MS.POWERBI.2.1v1 MS.POWERBI.3.1v1 "
        "MS.POWERBI.4.1v1 MS.POWERBI.4.2v1 MS.POWERBI.5.1v1 "
        "MS.POWERBI.6.1v1 MS.POWERBI.7.1v1"
    ),
}
EXPECTED_POLICIES: Final = {
    product: frozenset(policy_text.split()) for product, policy_text in EXPECTED_POLICY_TEXT.items()
}
REGO_SIGNATURE: Final = re.compile(r"\b(input|data)\b|\bsome\s+\w+\s*\{|\bPolicyId\b|[{}]")
POLICY_ID_PATTERN: Final = re.compile(r"^MS\.[A-Z]+\.\d+\.\d+v\d+$")
type RowValue = str | int | bool | list[str] | None


@dataclass(frozen=True, slots=True)
class ValidationResult:
    policy_count: int
    untracked_count: int
    baseline_total: int
    product_counts: Mapping[str, int]
    sha256: str
    errors: tuple[str, ...]

    @property
    def error_codes(self) -> tuple[str, ...]:
        return tuple(error.split(":", 1)[0] for error in self.errors)


def validate_manifest(path: Path) -> ValidationResult:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return ValidationResult(0, 0, 0, {}, _sha256(text), (f"malformed_yaml:{exc}",))
    if not isinstance(raw, dict):
        return ValidationResult(0, 0, 0, {}, _sha256(text), ("malformed_manifest:root",))
    policies = raw.get("policies")
    if not isinstance(policies, list):
        return ValidationResult(0, 0, 0, {}, _sha256(text), ("malformed_manifest:policies",))
    untracked = raw.get("untracked_policies") or []
    if not isinstance(untracked, list):
        return ValidationResult(
            0, 0, 0, {}, _sha256(text), ("malformed_manifest:untracked_policies",)
        )

    seen: set[str] = set()
    product_counts: Counter[str] = Counter()
    observed: dict[str, set[str]] = {product: set() for product in EXPECTED_POLICIES}
    for index, row in enumerate(policies):
        if not isinstance(row, dict):
            errors.append(f"malformed_row:{index}")
            continue
        errors.extend(_validate_row(row, index))
        product = row.get("product")
        policy_id = row.get("policy_id")
        if isinstance(product, str) and isinstance(policy_id, str):
            product_counts[product] += 1
            if policy_id in seen:
                errors.append(f"duplicate_policy:{policy_id}")
            seen.add(policy_id)
            if product in observed:
                observed[product].add(policy_id)

    untracked_seen: set[str] = set()
    for index, entry in enumerate(untracked):
        if not isinstance(entry, dict):
            errors.append(f"malformed_untracked_row:{index}")
            continue
        errors.extend(_validate_untracked_row(entry, index))
        product = entry.get("product")
        policy_id = entry.get("policy_id")
        if isinstance(product, str) and isinstance(policy_id, str):
            if policy_id in untracked_seen:
                errors.append(f"duplicate_untracked_policy:{policy_id}")
            untracked_seen.add(policy_id)
            if policy_id in seen:
                errors.append(f"untracked_already_mapped:{policy_id}")
            if product in observed:
                observed[product].add(policy_id)

    for product, expected_ids in EXPECTED_POLICIES.items():
        missing = sorted(expected_ids - observed[product])
        extra = sorted(observed[product] - expected_ids)
        errors.extend(f"missing_policy:{product}:{policy_id}" for policy_id in missing)
        errors.extend(f"unknown_policy:{product}:{policy_id}" for policy_id in extra)
    baseline_total = len(policies) + len(untracked)
    if baseline_total != BASELINE_TOTAL:
        errors.append(f"baseline_total_mismatch:{baseline_total}")
    return ValidationResult(
        len(policies),
        len(untracked),
        baseline_total,
        dict(sorted(product_counts.items())),
        _sha256(text),
        tuple(errors),
    )


def _validate_untracked_row(row: dict[str, RowValue], index: int) -> list[str]:
    errors: list[str] = []
    fields = set(row)
    extra = sorted(fields - UNTRACKED_ALLOWED_FIELDS)
    errors.extend(f"untracked_unknown_field:{index}:{field}" for field in extra)
    for field in UNTRACKED_ALLOWED_FIELDS:
        if field not in row:
            errors.append(f"untracked_missing_field:{index}:{field}")
    product = row.get("product")
    policy_id = row.get("policy_id")
    source_url = row.get("source_url")
    if not isinstance(product, str) or product not in EXPECTED_POLICIES:
        errors.append(f"untracked_invalid_product:{index}:{product}")
    if not isinstance(policy_id, str) or POLICY_ID_PATTERN.fullmatch(policy_id) is None:
        errors.append(f"untracked_invalid_policy_id:{index}:{policy_id}")
    else:
        expected_ids = EXPECTED_POLICIES.get(product)
        if not isinstance(expected_ids, frozenset) or policy_id not in expected_ids:
            errors.append(f"untracked_not_in_baseline:{product}:{policy_id}")
    rationale = row.get("rationale")
    if not isinstance(rationale, str) or len(rationale.split()) > 12:
        errors.append(f"untracked_invalid_rationale:{index}")
    if isinstance(source_url, str):
        errors.extend(_validate_any_baseline_url(source_url, index))
    else:
        errors.append(f"untracked_unpinned_source_url:{index}")
    return errors


def _validate_any_baseline_url(source_url: str, index: int) -> list[str]:
    for path in PRODUCT_PATHS.values():
        prefix = f"https://github.com/cisagov/ScubaGear/blob/{PINNED_COMMIT}/{path}#L"
        if not source_url.startswith(prefix):
            continue
        line_text = source_url.removeprefix(prefix)
        if line_text.isdigit() and line_text != "0":
            return []
        return [f"invalid_source_line:{index}"]
    return [f"untracked_unpinned_source_url:{index}"]


def _validate_row(row: dict[str, RowValue], index: int) -> list[str]:
    errors: list[str] = []
    fields = set(row)
    forbidden = sorted(fields & FORBIDDEN_FIELDS)
    errors.extend(f"forbidden_field:{index}:{field}" for field in forbidden)
    extra = sorted(fields - ALLOWED_FIELDS)
    errors.extend(f"unknown_field:{index}:{field}" for field in extra)
    for field in ALLOWED_FIELDS:
        if field not in row:
            errors.append(f"missing_field:{index}:{field}")
    product = row.get("product")
    policy_id = row.get("policy_id")
    source_url = row.get("source_url")
    pinned_commit = row.get("pinned_commit")
    if not isinstance(product, str) or product not in EXPECTED_POLICIES:
        errors.append(f"invalid_product:{index}:{product}")
    if not isinstance(policy_id, str) or POLICY_ID_PATTERN.fullmatch(policy_id) is None:
        errors.append(f"invalid_policy_id:{index}:{policy_id}")
    errors.extend(_validate_literals(row, index))
    if isinstance(policy_id, str):
        expected_version = "v" + policy_id.rsplit("v", 1)[-1]
        if row.get("policy_version") != expected_version:
            errors.append(f"invalid_policy_version:{index}:{policy_id}")
    if pinned_commit != PINNED_COMMIT:
        errors.append(f"unpinned_commit:{index}")
    if isinstance(product, str) and isinstance(source_url, str):
        errors.extend(_validate_source_url(product, source_url, index))
    else:
        errors.append(f"unpinned_source_url:{index}")
    for value in row.values():
        if isinstance(value, str) and REGO_SIGNATURE.search(value):
            errors.append(f"rego_signature:{index}")
            break
    return errors


def _validate_literals(row: dict[str, RowValue], index: int) -> list[str]:
    errors: list[str] = []
    if row.get("criticality") not in {"SHALL", "SHOULD"}:
        errors.append(f"invalid_criticality:{index}")
    if row.get("check_type") not in {"automated", "manual"}:
        errors.append(f"invalid_check_type:{index}")
    if row.get("disposition") not in DISPOSITIONS:
        errors.append(f"invalid_disposition:{index}")
    local_ids = row.get("local_check_ids")
    if not isinstance(local_ids, list) or not all(isinstance(item, str) for item in local_ids):
        errors.append(f"invalid_local_check_ids:{index}")
    rationale = row.get("rationale")
    if not isinstance(rationale, str) or len(rationale.split()) > 12:
        errors.append(f"invalid_rationale:{index}")
    return errors


def _validate_source_url(product: str, source_url: str, index: int) -> list[str]:
    path = PRODUCT_PATHS.get(product)
    if path is None:
        return [f"unpinned_source_url:{index}"]
    prefix = f"https://github.com/cisagov/ScubaGear/blob/{PINNED_COMMIT}/{path}#L"
    if not source_url.startswith(prefix):
        return [f"unpinned_source_url:{index}"]
    line_text = source_url.removeprefix(prefix)
    if not line_text.isdigit() or line_text == "0":
        return [f"invalid_source_line:{index}"]
    return []


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    path = Path(args[0]) if args else Path("catalog/coverage/scuba-2026-08.yaml")
    result = validate_manifest(path)
    print(f"policy_count={result.policy_count}")
    print(f"untracked_count={result.untracked_count}")
    print(f"baseline_total={result.baseline_total}")
    print(f"product_counts={result.product_counts}")
    print(f"sha256={result.sha256}")
    for error in result.errors:
        print(error)
    return 1 if result.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
