"""Aggregate collaboration offline fixtures for collectors and tests."""

from __future__ import annotations

from typing import Final

from licenselens.collectors.collaboration_fixtures_spo import DEMO_SPO_TENANT_PAYLOAD
from licenselens.collectors.collaboration_fixtures_teams import (
    DEMO_TEAMS_APPS_PAYLOAD,
    DEMO_TEAMS_CLIENT_PAYLOAD,
    DEMO_TEAMS_FEDERATION_PAYLOAD,
    DEMO_TEAMS_MEETING_PAYLOAD,
)
from licenselens.collectors.collaboration_models import (
    SPO_ADAPTER,
    TEAMS_APPS_ADAPTER,
    TEAMS_CLIENT_ADAPTER,
    TEAMS_FEDERATION_ADAPTER,
    TEAMS_MEETING_ADAPTER,
)
from licenselens.schema_contracts import JsonValue

DEMO_FIXTURES: Final[dict[str, dict[str, JsonValue]]] = {
    SPO_ADAPTER: DEMO_SPO_TENANT_PAYLOAD,
    TEAMS_MEETING_ADAPTER: DEMO_TEAMS_MEETING_PAYLOAD,
    TEAMS_FEDERATION_ADAPTER: DEMO_TEAMS_FEDERATION_PAYLOAD,
    TEAMS_CLIENT_ADAPTER: DEMO_TEAMS_CLIENT_PAYLOAD,
    TEAMS_APPS_ADAPTER: DEMO_TEAMS_APPS_PAYLOAD,
}

__all__ = [
    "DEMO_FIXTURES",
    "DEMO_SPO_TENANT_PAYLOAD",
    "DEMO_TEAMS_APPS_PAYLOAD",
    "DEMO_TEAMS_CLIENT_PAYLOAD",
    "DEMO_TEAMS_FEDERATION_PAYLOAD",
    "DEMO_TEAMS_MEETING_PAYLOAD",
]
