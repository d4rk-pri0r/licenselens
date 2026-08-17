"""Human-friendly display names for SKU part numbers and service plan names."""

from __future__ import annotations

from functools import lru_cache
from typing import Final

import yaml

from licenselens.paths import catalog_dir

#: Per-token fallback replacements for known acronyms, applied after splitting
#: an unknown name on underscores.
_ACRONYM_TOKENS: Final[dict[str, str]] = {
    "AAD": "Entra ID",
    "ATP": "Defender for Office 365",
    "MDO": "Defender for Office 365",
    "MDE": "Defender for Endpoint",
    "MDI": "Defender for Identity",
    "MIP": "Purview Information Protection",
    "EOP": "Exchange Online Protection",
    "DLP": "DLP",
    "MDM": "Intune",
    "EXCHANGE": "Exchange",
    "SHAREPOINT": "SharePoint",
    "TEAMS": "Teams",
    "INTUNE": "Intune",
    "PBI": "Power BI",
    "FLOW": "Power Apps",
    "POWERAPPS": "Power Apps",
    "O365": "Microsoft 365",
    "M365": "Microsoft 365",
    "SENTINEL": "Sentinel",
    "PURVIEW": "Purview",
    "EMS": "Enterprise Mobility + Security",
    "SKU": "SKU",
    "CLP1": "P1",
    "CLP2": "P2",
}


def _normalize(value: str) -> str:
    return value.strip().upper()


def _load_maps() -> tuple[dict[str, str], dict[str, str]]:
    path = catalog_dir() / "sku_service_plans.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    sku_map: dict[str, str] = {}
    for note in raw.get("notes") or []:
        part_number = note.get("sku_part_number")
        common_name = note.get("common_name")
        if part_number and common_name:
            sku_map.setdefault(_normalize(str(part_number)), str(common_name))
    for key, value in (raw.get("friendly_sku_names") or {}).items():
        sku_map[_normalize(str(key))] = str(value)
    plan_map: dict[str, str] = {
        _normalize(str(key)): str(value)
        for key, value in (raw.get("friendly_plan_names") or {}).items()
    }
    return sku_map, plan_map


@lru_cache(maxsize=1)
def _friendly_maps() -> tuple[dict[str, str], dict[str, str]]:
    return _load_maps()


def _fallback_friendly(name: str) -> str:
    tokens = name.split("_")
    parts: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        upper = token.upper()
        if upper == "BI" and index + 1 < len(tokens) and tokens[index + 1].upper() == "AZURE":
            parts.append("Power BI")
            index += 2
            continue
        parts.append(_ACRONYM_TOKENS.get(upper, token.title()))
        index += 1
    return " ".join(part for part in parts if part)


def friendly_sku_name(part_number: str) -> str:
    value = part_number.strip()
    if not value:
        return ""
    sku_map, _ = _friendly_maps()
    return sku_map.get(value.upper(), _fallback_friendly(value))


def friendly_plan_name(plan_name: str) -> str:
    value = plan_name.strip()
    if not value:
        return ""
    _, plan_map = _friendly_maps()
    return plan_map.get(value.upper(), _fallback_friendly(value))
