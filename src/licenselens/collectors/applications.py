"""Collect applications, service principals, and OAuth2 permission grants."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.contracts import EvidenceEnvelope
from licenselens.collectors.graph_collect import SupportsGraphReads, collect_graph_operation
from licenselens.graph import GraphClient

__all__ = [
    "DEMO_APPLICATIONS_BUNDLE",
    "collect_applications",
    "collect_applications_bundle",
    "collect_applications_evidence",
    "collect_oauth2_permission_grants",
    "collect_service_principals",
]


def collect_applications(client: GraphClient) -> list[dict[str, Any]]:
    select = "id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials"
    return client.get_list(
        "/applications",
        params={"$select": select},
        max_pages=40,
    )


def collect_service_principals(client: GraphClient) -> list[dict[str, Any]]:
    return client.get_list(
        "/servicePrincipals",
        params={"$select": "id,appId,displayName,accountEnabled,appOwnerOrganizationId"},
        max_pages=40,
    )


def collect_oauth2_permission_grants(client: GraphClient) -> list[dict[str, Any]]:
    return client.get_list("/oauth2PermissionGrants", max_pages=40)


def collect_applications_evidence(client: SupportsGraphReads) -> dict[str, EvidenceEnvelope]:
    return {
        "applications": collect_graph_operation(client, "applications"),
        "service_principals": collect_graph_operation(client, "service_principals"),
        "oauth2_permission_grants": collect_graph_operation(client, "oauth2_permission_grants"),
    }


def collect_applications_bundle(client: GraphClient) -> dict[str, Any]:
    return {
        "applications": collect_applications(client),
        "service_principals": collect_service_principals(client),
        "oauth2_permission_grants": collect_oauth2_permission_grants(client),
    }


DEMO_APPLICATIONS_BUNDLE: dict[str, Any] = {
    "applications": [
        {
            "id": "app-1",
            "appId": "11111111-1111-1111-1111-111111111111",
            "displayName": "Legacy Line-of-Business",
            "passwordCredentials": [{"displayName": "old-secret", "endDateTime": "2024-01-01"}],
            "keyCredentials": [],
        }
    ],
    "service_principals": [
        {
            "id": "sp-1",
            "appId": "11111111-1111-1111-1111-111111111111",
            "displayName": "Legacy Line-of-Business",
            "accountEnabled": True,
        }
    ],
    "oauth2_permission_grants": [
        {
            "id": "grant-1",
            "clientId": "sp-1",
            "consentType": "AllPrincipals",
            "scope": "User.Read Mail.Read",
        }
    ],
}
