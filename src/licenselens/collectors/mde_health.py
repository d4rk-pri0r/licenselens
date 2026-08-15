"""MDE machine healthStatus collection (bounded sample)."""

from __future__ import annotations

from collections import Counter
from typing import Any

from licenselens.auth import AuthContext
from licenselens.cloud_endpoints import UnsupportedCloudError
from licenselens.collectors.contracts import (
    CloudEnvironment,
    CollectionMetadata,
    EvidenceEnvelope,
    EvidenceHealth,
    EvidenceKey,
    PaginationMetadata,
)
from licenselens.collectors.graph_collect import map_graph_error
from licenselens.collectors.mde import MdeClient
from licenselens.errors import AuthError, GraphError

__all__ = [
    "DEMO_MDE_HEALTH",
    "collect_mde_health_evidence",
    "collect_mde_health_summary",
]


def collect_mde_health_summary(
    auth: AuthContext,
    *,
    cloud: CloudEnvironment = CloudEnvironment.PUBLIC,
    client: MdeClient | None = None,
    max_pages: int = 10,
) -> dict[str, Any]:
    owns = client is None
    mde = client if client is not None else MdeClient(auth, cloud=cloud)
    try:
        health_counts: Counter[str] = Counter()
        total = 0
        top = 200
        skip = 0
        pages = 0
        while pages < max_pages:
            data = mde.get(
                "/machines",
                params={
                    "$top": str(top),
                    "$skip": str(skip),
                    "$select": "id,healthStatus,onboardingStatus,riskScore",
                },
            )
            value = data.get("value") or []
            if not isinstance(value, list) or not value:
                break
            for row in value:
                if not isinstance(row, dict):
                    continue
                total += 1
                status = str(row.get("healthStatus") or "Unknown")
                health_counts[status] += 1
            if len(value) < top:
                break
            skip += top
            pages += 1
        truncated = pages >= max_pages and total > 0
        return {
            "machines_sampled": total,
            "health_status_counts": dict(sorted(health_counts.items())),
            "active_healthy": health_counts.get("Active", 0),
            "impaired_communication": health_counts.get("ImpairedCommunication", 0),
            "no_sensor_data": health_counts.get("NoSensorData", 0),
            "truncated": truncated,
            "count_method": "paged_health_sample",
        }
    finally:
        if owns:
            mde.close()


def collect_mde_health_evidence(
    auth: AuthContext,
    *,
    cloud: CloudEnvironment = CloudEnvironment.PUBLIC,
    client: MdeClient | None = None,
) -> EvidenceEnvelope:
    key = EvidenceKey("mde.machine_health")
    try:
        summary = collect_mde_health_summary(auth, cloud=cloud, client=client)
    except UnsupportedCloudError as exc:
        return EvidenceEnvelope.unsupported(key, reason=str(exc))
    except AuthError as exc:
        return EvidenceEnvelope.denied(key, reason=str(exc))
    except GraphError as exc:
        return map_graph_error(key, exc, source="mde_machine_health")
    health = EvidenceHealth.TRUNCATED if summary.get("truncated") else EvidenceHealth.OK
    return EvidenceEnvelope(
        key=key,
        health=health,
        value=summary,
        metadata=CollectionMetadata(
            source="mde_machine_health",
            items_collected=int(summary.get("machines_sampled") or 0),
            pagination=PaginationMetadata(
                pages_read=1,
                max_pages=10,
                next_link_seen=bool(summary.get("truncated")),
            ),
        ),
        reason="truncated sample" if health is EvidenceHealth.TRUNCATED else "",
    )


DEMO_MDE_HEALTH: dict[str, Any] = {
    "machines_sampled": 40,
    "health_status_counts": {"Active": 32, "ImpairedCommunication": 5, "NoSensorData": 3},
    "active_healthy": 32,
    "impaired_communication": 5,
    "no_sensor_data": 3,
    "truncated": False,
    "count_method": "demo",
}
