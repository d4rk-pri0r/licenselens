"""Collect risky service principals (workload identity protection) from Graph."""

from __future__ import annotations

from typing import Any

from licenselens.graph import GraphClient

__all__ = [
    "DEMO_RISKY_SERVICE_PRINCIPALS",
    "collect_risky_service_principals",
]


def collect_risky_service_principals(client: GraphClient) -> list[dict[str, Any]]:
    """GET /identityProtection/riskyServicePrincipals — risky workload identities."""
    return client.get_list("/identityProtection/riskyServicePrincipals", max_pages=10)


# Dry-run: no risky service principals (clean tenant)
DEMO_RISKY_SERVICE_PRINCIPALS: list[dict[str, Any]] = []
