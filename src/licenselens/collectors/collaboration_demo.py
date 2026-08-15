"""Dry-run evidence builder for Teams and SharePoint/OneDrive collection."""

from __future__ import annotations

from licenselens.collectors.collaboration_fixtures import (
    DEMO_FIXTURES,
    DEMO_SPO_TENANT_PAYLOAD,
    DEMO_TEAMS_APPS_PAYLOAD,
    DEMO_TEAMS_CLIENT_PAYLOAD,
    DEMO_TEAMS_FEDERATION_PAYLOAD,
    DEMO_TEAMS_MEETING_PAYLOAD,
)
from licenselens.collectors.collaboration_models import CollaborationBundle
from licenselens.collectors.collaboration_normalize import normalize_adapter_payload
from licenselens.schema_contracts import JsonValue

__all__ = [
    "DEMO_FIXTURES",
    "DEMO_SPO_TENANT_PAYLOAD",
    "DEMO_TEAMS_APPS_PAYLOAD",
    "DEMO_TEAMS_CLIENT_PAYLOAD",
    "DEMO_TEAMS_FEDERATION_PAYLOAD",
    "DEMO_TEAMS_MEETING_PAYLOAD",
    "demo_collaboration_evidence",
]


def demo_collaboration_evidence() -> dict[str, JsonValue]:
    """Dry-run evidence with global/custom collaboration fixtures (no live modules)."""
    adapters = {
        name: normalize_adapter_payload(payload, adapter=name)
        for name, payload in DEMO_FIXTURES.items()
    }
    bundle = CollaborationBundle(adapters=adapters, direct=True, proxy=False)
    return {
        "collaboration_bundle": bundle.model_dump(mode="json"),
        "collaboration_direct": True,
        "collaboration_proxy": False,
        "source": "powershell.collaboration",
        "proxy": False,
    }
