"""Collect security defaults policy state from Microsoft Graph."""

from __future__ import annotations

from typing import Any

from licenselens.graph import GraphClient


def collect_security_defaults_policy(client: GraphClient) -> dict[str, Any] | None:
    """GET /policies/identitySecurityDefaultsEnforcementPolicy — returns enabled state."""
    return client.get("/policies/identitySecurityDefaultsEnforcementPolicy")


# Dry-run: security defaults ON (common mid-maturity gap)
DEMO_SECURITY_DEFAULTS: dict[str, Any] = {
    "id": "00000000-0000-0000-0000-000000000005",
    "isEnabled": True,
}
