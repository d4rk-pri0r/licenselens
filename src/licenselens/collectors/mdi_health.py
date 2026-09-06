"""Collect Defender for Identity sensors and health issues (Graph v1.0)."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.device_hash import hash_device_label
from licenselens.graph import GraphClient

__all__ = [
    "DEMO_MDI_HEALTH",
    "UNHEALTHY_DEPLOYMENT",
    "collect_mdi_health",
]

UNHEALTHY_DEPLOYMENT: frozenset[str] = frozenset({"disconnected", "unreachable", "startFailure"})


def _row_unhealthy(row: dict[str, Any]) -> bool:
    health = str(row.get("healthStatus") or "").strip()
    deploy = str(row.get("deploymentStatus") or "").strip()
    if health and health != "healthy":
        return True
    return deploy in UNHEALTHY_DEPLOYMENT


def collect_mdi_health(client: GraphClient) -> dict[str, Any]:
    sensors_raw = client.get_list(
        "/security/identities/sensors",
        params={
            "$select": (
                "id,displayName,domainName,healthStatus,"
                "deploymentStatus,openHealthIssuesCount,sensorType"
            )
        },
        max_pages=20,
    )
    issues_raw = client.get_list(
        "/security/identities/healthIssues",
        params={"$select": "id,status,healthIssueType,severity,displayName"},
        max_pages=20,
    )
    sensors: list[dict[str, Any]] = []
    unhealthy = 0
    for item in sensors_raw:
        if not isinstance(item, dict):
            continue
        unhealthy_flag = _row_unhealthy(item)
        if unhealthy_flag:
            unhealthy += 1
        sensors.append(
            {
                "id": item.get("id"),
                "displayName_hash": hash_device_label(item.get("displayName")),
                "domainName_hash": hash_device_label(item.get("domainName")),
                "healthStatus": item.get("healthStatus"),
                "deploymentStatus": item.get("deploymentStatus"),
                "openHealthIssuesCount": item.get("openHealthIssuesCount") or 0,
                "sensorType": item.get("sensorType"),
                "unhealthy": unhealthy_flag,
            }
        )
    open_issues = 0
    for item in issues_raw:
        if isinstance(item, dict) and str(item.get("status") or "").lower() == "open":
            open_issues += 1
    return {
        "direct": True,
        "sensor_count": len(sensors),
        "unhealthy_count": unhealthy,
        "open_health_issues": open_issues,
        "sensors": sensors,
    }


DEMO_MDI_HEALTH: dict[str, Any] = {
    "direct": False,
    "sensor_count": 0,
    "unhealthy_count": 0,
    "open_health_issues": 0,
    "sensors": [],
}
