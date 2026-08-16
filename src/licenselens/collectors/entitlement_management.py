"""Collect Entitlement Management access packages from Microsoft Graph."""

from __future__ import annotations

from typing import Any

from licenselens.graph import GraphClient


def collect_access_packages(client: GraphClient) -> list[dict[str, Any]]:
    """GET /identityGovernance/entitlementManagement/accessPackages (all pages)."""
    return client.get_list(
        "/identityGovernance/entitlementManagement/accessPackages",
        max_pages=10,
    )


# Dry-run: one starter access package (lifecycle-governed access partially adopted)
DEMO_ACCESS_PACKAGES: list[dict[str, Any]] = [
    {
        "id": "demo-access-package-1",
        "displayName": "Demo: Contractor starter access",
        "description": "Baseline access for contractors",
        "isHidden": False,
        "isRoleScopesVisible": False,
        "catalogId": "demo-catalog-1",
        "createdDateTime": "2026-01-15T00:00:00Z",
        "modifiedDateTime": "2026-02-01T00:00:00Z",
    }
]
