"""Collect Graph security incidents and alerts (capability operation signals)."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.contracts import EvidenceEnvelope
from licenselens.collectors.graph_collect import SupportsGraphReads, collect_graph_operation
from licenselens.graph import GraphClient

__all__ = [
    "DEMO_SECURITY_ALERTS_BUNDLE",
    "collect_security_alerts",
    "collect_security_alerts_bundle",
    "collect_security_alerts_evidence",
    "collect_security_incidents",
]


def collect_security_incidents(client: GraphClient) -> list[dict[str, Any]]:
    return client.get_list(
        "/security/incidents",
        params={"$top": "50", "$select": "id,displayName,status,severity,createdDateTime"},
        max_pages=10,
    )


def collect_security_alerts(client: GraphClient) -> list[dict[str, Any]]:
    return client.get_list(
        "/security/alerts_v2",
        params={"$top": "50", "$select": "id,title,severity,status,createdDateTime,serviceSource"},
        max_pages=10,
    )


def collect_security_alerts_evidence(client: SupportsGraphReads) -> dict[str, EvidenceEnvelope]:
    return {
        "security_incidents": collect_graph_operation(client, "security_incidents"),
        "security_alerts": collect_graph_operation(client, "security_alerts_v2"),
    }


def collect_security_alerts_bundle(client: GraphClient) -> dict[str, Any]:
    incidents = collect_security_incidents(client)
    alerts = collect_security_alerts(client)
    return {
        "incidents": incidents,
        "alerts": alerts,
        "incident_count": len(incidents),
        "alert_count": len(alerts),
        "capability_operating": bool(incidents or alerts),
    }


DEMO_SECURITY_ALERTS_BUNDLE: dict[str, Any] = {
    "incidents": [
        {
            "id": "inc-1",
            "displayName": "Demo multi-stage incident",
            "status": "active",
            "severity": "medium",
        }
    ],
    "alerts": [
        {
            "id": "alert-1",
            "title": "Demo suspicious sign-in",
            "severity": "medium",
            "status": "new",
            "serviceSource": "azureAdIdentityProtection",
        }
    ],
    "incident_count": 1,
    "alert_count": 1,
    "capability_operating": True,
}
