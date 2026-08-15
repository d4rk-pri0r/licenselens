"""Collect guest users and cross-tenant access policy settings."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.contracts import EvidenceEnvelope
from licenselens.collectors.graph_collect import SupportsGraphReads, collect_graph_operation
from licenselens.graph import GraphClient

__all__ = [
    "DEMO_GUESTS_BUNDLE",
    "collect_cross_tenant_access_default",
    "collect_cross_tenant_access_partners",
    "collect_cross_tenant_access_policy",
    "collect_guest_users",
    "collect_guests_bundle",
    "collect_guests_evidence",
]

_GUEST_FILTER = "userType eq 'Guest'"
_GUEST_SELECT = "id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime"


def collect_cross_tenant_access_policy(client: GraphClient) -> dict[str, Any]:
    return client.get("/policies/crossTenantAccessPolicy")


def collect_cross_tenant_access_default(client: GraphClient) -> dict[str, Any]:
    return client.get("/policies/crossTenantAccessPolicy/default")


def collect_cross_tenant_access_partners(client: GraphClient) -> list[dict[str, Any]]:
    return client.get_list("/policies/crossTenantAccessPolicy/partners", max_pages=20)


def collect_guest_users(client: GraphClient) -> list[dict[str, Any]]:
    return client.get_list(
        "/users",
        params={"$filter": _GUEST_FILTER, "$select": _GUEST_SELECT},
        max_pages=40,
    )


def collect_guests_evidence(client: SupportsGraphReads) -> dict[str, EvidenceEnvelope]:
    return {
        "cross_tenant_access_policy": collect_graph_operation(client, "cross_tenant_access_policy"),
        "cross_tenant_access_default": collect_graph_operation(
            client, "cross_tenant_access_default"
        ),
        "cross_tenant_access_partners": collect_graph_operation(
            client, "cross_tenant_access_partners"
        ),
        "guest_users": collect_graph_operation(
            client,
            "guest_users",
            params={"$filter": _GUEST_FILTER, "$select": _GUEST_SELECT},
        ),
    }


def collect_guests_bundle(client: GraphClient) -> dict[str, Any]:
    return {
        "policy": collect_cross_tenant_access_policy(client),
        "default": collect_cross_tenant_access_default(client),
        "partners": collect_cross_tenant_access_partners(client),
        "guests": collect_guest_users(client),
    }


DEMO_GUESTS_BUNDLE: dict[str, Any] = {
    "policy": {"displayName": "CrossTenantAccessPolicy"},
    "default": {
        "b2bCollaborationInbound": {"usersAndGroups": {"accessType": "allowed"}},
        "invitationRedemptionIdentityProviderConfiguration": {
            "primaryIdentityProviderPrecedenceOrder": ["azureActiveDirectory"]
        },
    },
    "partners": [],
    "guests": [
        {
            "id": "guest-1",
            "userPrincipalName": "alice_contoso.com#EXT#@fabrikam.onmicrosoft.com",
            "userType": "Guest",
            "accountEnabled": True,
        }
    ],
}
