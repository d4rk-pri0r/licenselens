"""Load and validate catalog/telemetry_expectations.yaml."""

from __future__ import annotations

from typing import Any, Final

import yaml

from licenselens.catalog.capability_meta import CatalogLoadError
from licenselens.catalog.loader import load_capabilities
from licenselens.paths import catalog_dir

_TIERS: Final = frozenset({"core", "extended"})
_LEARN_PREFIX: Final = "https://learn.microsoft.com/"


def load_telemetry_expectations(
    *,
    path: Any | None = None,
) -> dict[str, Any]:
    """Return the telemetry expectations document after strict validation."""
    catalog_path = path or (catalog_dir() / "telemetry_expectations.yaml")
    raw = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise CatalogLoadError(("telemetry_expectations_not_object",))
    known_ids = {cap.id for cap in load_capabilities()}
    rows = raw.get("expectations")
    if not isinstance(rows, list) or not rows:
        raise CatalogLoadError(("telemetry_expectations_missing",))
    seen: set[tuple[str, str]] = set()
    diagnostics: list[str] = []
    for item in rows:
        if not isinstance(item, dict):
            diagnostics.append("expectation_not_object")
            continue
        cap_id = str(item.get("capability_id") or "")
        if cap_id not in known_ids:
            diagnostics.append(f"unknown_capability:{cap_id}")
        tables = item.get("tables")
        if not isinstance(tables, list) or not tables:
            diagnostics.append(f"tables_missing:{cap_id}")
            continue
        for table in tables:
            if not isinstance(table, dict):
                diagnostics.append(f"table_not_object:{cap_id}")
                continue
            name = str(table.get("name") or "")
            if not name:
                diagnostics.append(f"table_name_missing:{cap_id}")
                continue
            key = (cap_id, name)
            if key in seen:
                diagnostics.append(f"duplicate_table:{cap_id}:{name}")
            seen.add(key)
            tier = str(table.get("tier") or "")
            if tier not in _TIERS:
                diagnostics.append(f"bad_tier:{cap_id}:{name}:{tier}")
            url = str(table.get("source_url") or "")
            if not url.startswith(_LEARN_PREFIX):
                diagnostics.append(f"source_url:{cap_id}:{name}")
    if diagnostics:
        raise CatalogLoadError(tuple(diagnostics))
    return raw


def telemetry_expectations_payload() -> dict[str, Any]:
    """JSON-ready copy for the noop collector."""
    return load_telemetry_expectations()
