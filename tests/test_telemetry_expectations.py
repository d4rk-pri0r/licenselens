"""WS3-A: telemetry expectations catalog loader."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from licenselens.catalog.capability_meta import CatalogLoadError
from licenselens.catalog.telemetry import load_telemetry_expectations
from licenselens.collectors.runtime_specs import _COLLECTORS


def test_expectations_load() -> None:
    doc = load_telemetry_expectations()
    ids = {row["capability_id"] for row in doc["expectations"]}
    assert "identity_protection" in ids
    assert "defender_endpoint_p2" in ids
    assert "la_usage_by_table" in _COLLECTORS
    assert "telemetry_expectations" in _COLLECTORS


def test_every_row_has_learn_url() -> None:
    doc = load_telemetry_expectations()
    for row in doc["expectations"]:
        for table in row["tables"]:
            assert str(table["source_url"]).startswith("https://learn.microsoft.com/")
            assert table["tier"] in {"core", "extended"}


def test_unknown_capability_rejected(tmp_path: Path) -> None:
    payload = {
        "version": 1,
        "source_version": "2026-09",
        "expectations": [
            {
                "capability_id": "not_a_real_capability",
                "tables": [
                    {
                        "name": "SigninLogs",
                        "tier": "core",
                        "source_url": "https://learn.microsoft.com/azure/sentinel/data-connectors/microsoft-entra-id",
                    }
                ],
            }
        ],
    }
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    with pytest.raises(CatalogLoadError) as exc:
        load_telemetry_expectations(path=path)
    assert "unknown_capability:not_a_real_capability" in str(exc.value)
