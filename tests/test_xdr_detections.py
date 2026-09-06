"""WS3-C: XDR custom detections collector (Graph beta / preview)."""

from __future__ import annotations

from licenselens.collectors.xdr_detections import (
    QUERY_TEXT_LIMIT,
    collect_xdr_custom_detections,
)
from licenselens.engine.registry import default_registry
from licenselens.graph_ops import get_operation
from tests.fake_clients import FakeGraphClient, ok


def test_collects_enabled_from_status() -> None:
    fake = FakeGraphClient(allow_preview=True)
    long_query = "DeviceProcessEvents | take 1" + ("x" * 5000)
    fake.register_list(
        "/security/rules/detectionRules",
        ok(
            {
                "value": [
                    {
                        "displayName": "on",
                        "status": "enabled",
                        "queryCondition": {"queryText": long_query},
                        "schedule": {"period": "12H"},
                    },
                    {
                        "displayName": "off",
                        "status": "disabled",
                        "queryCondition": {"queryText": "SigninLogs | take 1"},
                    },
                ]
            }
        ),
    )
    bundle = collect_xdr_custom_detections(fake)
    assert bundle["enabled_count"] == 1
    assert bundle["rules"][0]["isEnabled"] is True
    assert len(bundle["rules"][0]["queryText"]) == QUERY_TEXT_LIMIT
    assert bundle["rules"][1]["isEnabled"] is False


def test_preview_operation_is_beta() -> None:
    op = get_operation("graph_xdr_detection_rules")
    assert op.preview is True
    assert op.api_version == "beta"
    assert "CustomDetection.Read.All" in op.application_permissions


def test_collector_registered() -> None:
    registry = default_registry()
    assert "xdr_detections_collector" in {c.id for c in registry.collector_entries}
    assert "xdr_custom_detections" in {s.id for s in registry.data_source_entries}
