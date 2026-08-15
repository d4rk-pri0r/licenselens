"""Collect verified domains for password-expiration policy signals."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.contracts import EvidenceEnvelope
from licenselens.collectors.graph_collect import SupportsGraphReads, collect_graph_operation
from licenselens.graph import GraphClient

__all__ = [
    "DEMO_DOMAINS",
    "collect_domains",
    "collect_domains_evidence",
]


def collect_domains(client: GraphClient) -> list[dict[str, Any]]:
    return client.get_list(
        "/domains",
        params={"$select": "id,isVerified,isDefault,passwordValidityPeriodInDays"},
        max_pages=10,
    )


def collect_domains_evidence(client: SupportsGraphReads) -> EvidenceEnvelope:
    return collect_graph_operation(client, "domains")


DEMO_DOMAINS: list[dict[str, Any]] = [
    {
        "id": "contoso.onmicrosoft.com",
        "isVerified": True,
        "isDefault": True,
        "passwordValidityPeriodInDays": 90,
    }
]
