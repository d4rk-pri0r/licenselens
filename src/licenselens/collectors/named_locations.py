"""Collect Conditional Access named locations."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.contracts import EvidenceEnvelope
from licenselens.collectors.graph_collect import SupportsGraphReads, collect_graph_operation
from licenselens.graph import GraphClient

__all__ = [
    "DEMO_NAMED_LOCATIONS",
    "collect_named_locations",
    "collect_named_locations_evidence",
]


def collect_named_locations(client: GraphClient) -> list[dict[str, Any]]:
    return client.get_list("/identity/conditionalAccess/namedLocations", max_pages=20)


def collect_named_locations_evidence(client: SupportsGraphReads) -> EvidenceEnvelope:
    return collect_graph_operation(client, "ca_named_locations")


DEMO_NAMED_LOCATIONS: list[dict[str, Any]] = [
    {
        "id": "nl-corp",
        "displayName": "Corporate egress",
        "@odata.type": "#microsoft.graph.ipNamedLocation",
        "isTrusted": True,
        "ipRanges": [{"cidrAddress": "203.0.113.0/24"}],
    },
    {
        "id": "nl-blocked-countries",
        "displayName": "Blocked countries",
        "@odata.type": "#microsoft.graph.countryNamedLocation",
        "countriesAndRegions": ["KP", "RU"],
        "includeUnknownCountriesAndRegions": False,
    },
]
