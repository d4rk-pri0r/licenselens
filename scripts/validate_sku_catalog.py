#!/usr/bin/env python3
"""Offline validator for the GUID-backed SKU / service-plan catalog.

Guards the licensing-entitlement trust boundary without a tenant:

1. Every ``service_plan_id`` GUID in ``catalog/capabilities.yaml`` is a
   well-formed GUID and maps to exactly ONE capability (no duplicates).
2. The GUID<->name map in ``catalog/sku_service_plans.yaml`` is consistent
   with capabilities.yaml: every mapped GUID belongs to exactly one
   capability, the mapped canonical name matches that capability's service
   plan names, and every capability that references a mapped plan name also
   carries the GUID (no name-only half-migration).

Exit code 1 with one violation per line when anything fails; 0 when clean.

Usage: python scripts/validate_sku_catalog.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Final

import yaml

_GUID_PATTERN: Final = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys."""


def _construct_unique_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False):
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_yaml(path: Path) -> dict:
    return _UniqueKeyLoader(path.read_text(encoding="utf-8")).get_single_data() or {}


def validate_sku_catalog(
    capabilities_path: Path | None = None,
    map_path: Path | None = None,
) -> list[str]:
    """Return violation messages; an empty list means the catalog is consistent.

    Invariants enforced (a service plan GUID may legitimately unlock several
    capabilities, so cross-capability GUID sharing is expected — the checks
    below guard the trust boundary without over-constraining shared plans):

    1. Every ``service_plan_id`` GUID in capabilities.yaml is well-formed and
       appears at most once within a single capability's list.
    2. The GUID<->name map in sku_service_plans.yaml is a bijection: no GUID
       maps to two names and no name maps to two GUIDs.
    3. Every capability GUID is resolved by the map, and the mapped canonical
       name is one the capability actually references (no cross-wiring).
    4. Every capability that references a mapped plan name carries its GUID
       (no name-only half-migration).

    Violations name the offending capability so CI output points at the fix.
    """
    root = _repo_root()
    capabilities_path = capabilities_path or (root / "catalog" / "capabilities.yaml")
    map_path = map_path or (root / "catalog" / "sku_service_plans.yaml")

    violations: list[str] = []
    capabilities_raw = _load_yaml(capabilities_path)
    items = capabilities_raw.get("capabilities") or []
    if not isinstance(items, list) or not items:
        return ["capabilities.yaml: missing or empty 'capabilities' list"]

    guid_to_capabilities: dict[str, list[str]] = {}
    capability_names: dict[str, set[str]] = {}
    capability_guids: dict[str, set[str]] = {}
    for item in items:
        if not isinstance(item, dict) or not item.get("id"):
            violations.append("capabilities.yaml: capability entry missing 'id'")
            continue
        cap_id = str(item["id"])
        names = {
            str(n).upper()
            for n in [*(item.get("service_plan_names") or []),
                      *(item.get("service_plan_aliases") or [])]
        }
        capability_names[cap_id] = names
        listed_guids: set[str] = set()
        for raw_guid in item.get("service_plan_ids") or []:
            guid = str(raw_guid).strip().lower()
            if not _GUID_PATTERN.fullmatch(guid):
                violations.append(
                    f"capability '{cap_id}': service_plan_id {raw_guid!r} is not a valid GUID"
                )
                continue
            if guid in listed_guids:
                violations.append(
                    f"capability '{cap_id}': GUID {guid} listed more than once"
                )
            listed_guids.add(guid)
            guid_to_capabilities.setdefault(guid, []).append(cap_id)
        capability_guids[cap_id] = listed_guids

    map_raw = _load_yaml(map_path)
    guid_name_map = map_raw.get("service_plan_guids") or {}
    if not isinstance(guid_name_map, dict):
        violations.append("sku_service_plans.yaml: 'service_plan_guids' must be a mapping")
        guid_name_map = {}
    name_guid_map: dict[str, str] = {}
    for guid, name in guid_name_map.items():
        normalized_guid = str(guid).strip().lower()
        canonical_name = str(name or "").strip()
        if not _GUID_PATTERN.fullmatch(normalized_guid):
            violations.append(f"sku_service_plans.yaml: {guid!r} is not a valid GUID key")
            continue
        if not canonical_name:
            violations.append(f"sku_service_plans.yaml: GUID {normalized_guid} has an empty name")
            continue
        owners = guid_to_capabilities.get(normalized_guid)
        if not owners:
            violations.append(
                f"sku_service_plans.yaml: GUID {normalized_guid} ({canonical_name}) "
                "is not listed on any capability"
            )
            continue
        for owner in owners:
            if canonical_name.upper() not in capability_names.get(owner, set()):
                violations.append(
                    f"capability '{owner}': lists GUID {normalized_guid} which maps to name "
                    f"{canonical_name!r}, but '{owner}' does not reference that plan name "
                    f"(names: {sorted(capability_names.get(owner, set()))})"
                )
        existing_guid = name_guid_map.get(canonical_name.upper())
        if existing_guid is not None and existing_guid != normalized_guid:
            violations.append(
                f"sku_service_plans.yaml: name {canonical_name!r} maps to both GUID "
                f"{existing_guid} and GUID {normalized_guid}"
            )
        name_guid_map[canonical_name.upper()] = normalized_guid

    for cap_id, names in capability_names.items():
        listed_guids = capability_guids.get(cap_id, set())
        for name in sorted(names):
            mapped_guid = name_guid_map.get(name)
            if mapped_guid is not None and mapped_guid not in listed_guids:
                violations.append(
                    f"capability '{cap_id}': references mapped plan name {name!r} "
                    f"(GUID {mapped_guid}) but does not list that GUID in service_plan_ids"
                )

    return violations


def main() -> int:
    violations = validate_sku_catalog()
    if violations:
        print("SKU catalog validation FAILED:")
        for message in violations:
            print(f"  - {message}")
        return 1
    print("SKU catalog validation OK: every GUID maps to exactly one capability.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
