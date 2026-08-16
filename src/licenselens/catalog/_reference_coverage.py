from __future__ import annotations

import re
from pathlib import Path
from typing import Final, TypedDict
from urllib.parse import urlparse

import yaml
from pydantic import TypeAdapter

from licenselens.catalog._reference_models import (
    CoverageDisposition,
    ReferenceCoverageRow,
    ReferenceUntrackedRow,
)
from licenselens.models import PROXY_CHECK_IDS

type JsonValue = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
type JsonObject = dict[str, JsonValue]

YAML_OBJECT: Final = TypeAdapter(JsonObject)
POLICY_ID_PATTERN: Final = re.compile(r"^MS\.[A-Z]+\.\d+\.\d+v\d+$")
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
UNTRACKED_FIELDS: Final = frozenset({"product", "policy_id", "source_url", "rationale"})


class CoverageRow(TypedDict):
    product: str
    policy_id: str
    disposition: CoverageDisposition | None
    local_check_ids: list[str]
    source_url: str


def load_coverage_rows(
    path: Path,
    check_ids: set[str],
) -> tuple[list[ReferenceCoverageRow], list[str]]:
    raw = YAML_OBJECT.validate_python(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    rows = raw.get("policies")
    errors: list[str] = []
    coverage: list[ReferenceCoverageRow] = []
    if not isinstance(rows, list):
        return coverage, ["malformed_coverage:policies"]
    for index, raw_row in enumerate(rows):
        if not isinstance(raw_row, dict):
            errors.append(f"malformed_coverage_row:{index}")
            continue
        row = _coverage_row(raw_row)
        errors.extend(_validate_coverage_row(row, index, check_ids))
        if row["disposition"] is not None:
            coverage.append(
                ReferenceCoverageRow(
                    policy_id=row["policy_id"],
                    product=row["product"],
                    disposition=row["disposition"],
                    local_check_ids=tuple(sorted(row["local_check_ids"])),
                    source_path=_source_path(row["product"], row["source_url"]),
                )
            )
    return coverage, errors


def _parse_disposition(value: str) -> CoverageDisposition | None:
    try:
        return CoverageDisposition(value)
    except ValueError:
        return None


def _coverage_row(raw: JsonObject) -> CoverageRow:
    local = raw.get("local_check_ids")
    disposition = str(raw.get("disposition") or "")
    return {
        "product": str(raw.get("product") or ""),
        "policy_id": str(raw.get("policy_id") or ""),
        "disposition": _parse_disposition(disposition),
        "local_check_ids": [str(item) for item in local] if isinstance(local, list) else [],
        "source_url": str(raw.get("source_url") or ""),
    }


def _validate_coverage_row(row: CoverageRow, index: int, check_ids: set[str]) -> list[str]:
    errors: list[str] = []
    if row["product"] not in PRODUCT_PATHS or not _source_path(row["product"], row["source_url"]):
        errors.append(f"unresolved_coverage_path:{index}:{row['product']}")
    if POLICY_ID_PATTERN.fullmatch(row["policy_id"]) is None:
        errors.append(f"invalid_coverage_policy:{index}:{row['policy_id']}")
    errors.extend(
        f"unknown_coverage_check:{row['policy_id']}:{check_id}"
        for check_id in sorted(set(row["local_check_ids"]) - check_ids)
    )
    if row["disposition"] is None:
        errors.append(f"invalid_coverage_disposition:{index}")
    if (
        row["disposition"]
        in {
            CoverageDisposition.MANUAL,
            CoverageDisposition.UNSUPPORTED,
            CoverageDisposition.NOT_APPLICABLE,
        }
        and row["local_check_ids"]
    ):
        errors.append(f"contradictory_coverage_state:{row['policy_id']}:{row['disposition']}")
    if row["disposition"] == CoverageDisposition.IMPLEMENTED_DIRECT and any(
        check_id in PROXY_CHECK_IDS for check_id in row["local_check_ids"]
    ):
        errors.append(f"contradictory_coverage_state:{row['policy_id']}:implemented_direct")
    if row["disposition"] == CoverageDisposition.IMPLEMENTED_PROXY and any(
        check_id not in PROXY_CHECK_IDS for check_id in row["local_check_ids"]
    ):
        errors.append(f"contradictory_coverage_state:{row['policy_id']}:implemented_proxy")
    return errors


def load_untracked_rows(
    path: Path,
    mapped_policy_ids: set[str],
) -> tuple[list[ReferenceUntrackedRow], list[str]]:
    raw = YAML_OBJECT.validate_python(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    entries = raw.get("untracked_policies") or []
    errors: list[str] = []
    untracked: list[ReferenceUntrackedRow] = []
    if not isinstance(entries, list):
        return untracked, ["malformed_untracked:policies"]
    for index, raw_entry in enumerate(entries):
        if not isinstance(raw_entry, dict):
            errors.append(f"malformed_untracked_row:{index}")
            continue
        unknown = sorted(set(raw_entry) - UNTRACKED_FIELDS)
        errors.extend(f"unknown_untracked_field:{index}:{field}" for field in unknown)
        product = str(raw_entry.get("product") or "")
        policy_id = str(raw_entry.get("policy_id") or "")
        rationale = str(raw_entry.get("rationale") or "")
        source_path = _any_source_path(str(raw_entry.get("source_url") or ""))
        if product not in PRODUCT_PATHS or not source_path:
            errors.append(f"unresolved_untracked_path:{index}:{product}")
        if POLICY_ID_PATTERN.fullmatch(policy_id) is None:
            errors.append(f"invalid_untracked_policy:{index}:{policy_id}")
        if not rationale:
            errors.append(f"missing_untracked_rationale:{index}:{policy_id}")
        if policy_id in mapped_policy_ids:
            errors.append(f"untracked_already_mapped:{policy_id}")
        untracked.append(
            ReferenceUntrackedRow(
                policy_id=policy_id,
                product=product,
                rationale=rationale,
                source_path=source_path,
            )
        )
    return untracked, errors


def _any_source_path(source_url: str) -> str:
    parsed = urlparse(source_url)
    for path in PRODUCT_PATHS.values():
        if parsed.path.endswith(path):
            return path
    return ""


def _source_path(product: str, source_url: str) -> str:
    parsed = urlparse(source_url)
    expected_path = PRODUCT_PATHS.get(product, "")
    return expected_path if expected_path and parsed.path.endswith(expected_path) else ""
