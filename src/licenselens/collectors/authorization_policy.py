"""Collect Entra authorization and admin-consent policies."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.contracts import EvidenceEnvelope
from licenselens.collectors.graph_collect import SupportsGraphReads, collect_graph_operation
from licenselens.graph import GraphClient

__all__ = [
    "DEMO_AUTHORIZATION_BUNDLE",
    "collect_admin_consent_request_policy",
    "collect_authorization_bundle",
    "collect_authorization_evidence",
    "collect_authorization_policy",
]


def collect_authorization_policy(client: GraphClient) -> dict[str, Any]:
    return client.get("/policies/authorizationPolicy")


def collect_admin_consent_request_policy(client: GraphClient) -> dict[str, Any]:
    return client.get("/policies/adminConsentRequestPolicy")


def collect_authorization_evidence(client: SupportsGraphReads) -> dict[str, EvidenceEnvelope]:
    return {
        "authorization_policy": collect_graph_operation(client, "authorization_policy"),
        "admin_consent_request_policy": collect_graph_operation(
            client, "admin_consent_request_policy"
        ),
    }


def collect_authorization_bundle(client: GraphClient) -> dict[str, Any]:
    return {
        "authorization_policy": collect_authorization_policy(client),
        "admin_consent_request_policy": collect_admin_consent_request_policy(client),
    }


DEMO_AUTHORIZATION_BUNDLE: dict[str, Any] = {
    "authorization_policy": {
        "id": "authorizationPolicy",
        "defaultUserRolePermissions": {
            "allowedToCreateApps": True,
            "permissionGrantPoliciesAssigned": [
                "ManagePermissionGrantsForSelf.microsoft-user-default-legacy"
            ],
        },
        "allowInvitesFrom": "everyone",
        "guestUserRoleId": "a0b1b346-4d3e-4e8b-98f8-753987be4970",
    },
    "admin_consent_request_policy": {
        "isEnabled": False,
        "notifyReviewers": False,
        "remindersEnabled": False,
    },
}
