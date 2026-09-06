"""Collect Defender XDR custom detection rules (Graph beta)."""

from __future__ import annotations

from typing import Any

from licenselens.graph import GraphClient

__all__ = [
    "DEMO_XDR_CUSTOM_DETECTIONS",
    "QUERY_TEXT_LIMIT",
    "collect_xdr_custom_detections",
]

QUERY_TEXT_LIMIT = 4000
DETECTION_RULES_PATH = "/security/rules/detectionRules"

DEMO_XDR_CUSTOM_DETECTIONS: dict[str, Any] = {
    "rules": [],
    "enabled_count": 0,
}


def collect_xdr_custom_detections(client: GraphClient) -> dict[str, Any]:
    """List custom detection rules. Requires a preview-enabled Graph client."""
    raw = client.get_list(DETECTION_RULES_PATH, max_pages=10)
    rules: list[dict[str, Any]] = []
    enabled_count = 0
    for item in raw:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "")
        deprecated = item.get("isEnabled")
        is_enabled = status == "enabled" or (not status and deprecated is True)
        raw_condition = item.get("queryCondition")
        query_condition = raw_condition if isinstance(raw_condition, dict) else {}
        query_text = str(query_condition.get("queryText") or "")[:QUERY_TEXT_LIMIT]
        schedule = item.get("schedule") if isinstance(item.get("schedule"), dict) else {}
        display = str(item.get("displayName") or item.get("id") or "")
        rules.append(
            {
                "displayName": display,
                "isEnabled": is_enabled,
                "queryText": query_text,
                "schedule": dict(schedule),
                "status": status,
            }
        )
        if is_enabled:
            enabled_count += 1
    return {"rules": rules, "enabled_count": enabled_count}
