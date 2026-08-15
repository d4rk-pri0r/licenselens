"""Collect PIM role management policies and policy assignments."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.contracts import EvidenceEnvelope
from licenselens.collectors.graph_collect import SupportsGraphReads, collect_graph_operation
from licenselens.graph import GraphClient

__all__ = [
    "DEMO_PIM_POLICIES_BUNDLE",
    "collect_pim_policies_bundle",
    "collect_pim_policies_evidence",
    "collect_role_management_policies",
    "collect_role_management_policy_assignments",
]

_DIRECTORY_SCOPE_FILTER = "scopeId eq '/' and scopeType eq 'DirectoryRole'"


def collect_role_management_policies(client: GraphClient) -> list[dict[str, Any]]:
    return client.get_list(
        "/policies/roleManagementPolicies",
        params={"$filter": _DIRECTORY_SCOPE_FILTER},
        max_pages=20,
    )


def collect_role_management_policy_assignments(client: GraphClient) -> list[dict[str, Any]]:
    return client.get_list(
        "/policies/roleManagementPolicyAssignments",
        params={"$filter": _DIRECTORY_SCOPE_FILTER},
        max_pages=20,
    )


def collect_pim_policies_evidence(client: SupportsGraphReads) -> dict[str, EvidenceEnvelope]:
    return {
        "pim_role_management_policies": collect_graph_operation(
            client,
            "pim_role_management_policies",
            params={"$filter": _DIRECTORY_SCOPE_FILTER},
        ),
        "pim_role_management_policy_assignments": collect_graph_operation(
            client,
            "pim_role_management_policy_assignments",
            params={"$filter": _DIRECTORY_SCOPE_FILTER},
        ),
    }


def collect_pim_policies_bundle(client: GraphClient) -> dict[str, Any]:
    return {
        "policies": collect_role_management_policies(client),
        "assignments": collect_role_management_policy_assignments(client),
    }


DEMO_PIM_POLICIES_BUNDLE: dict[str, Any] = {
    "policies": [
        {
            "id": "policy-ga",
            "displayName": "DirectoryRole",
            "scopeId": "/",
            "scopeType": "DirectoryRole",
            "rules": [
                {
                    "id": "Expiration_EndUser_Assignment",
                    "@odata.type": ("#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"),
                    "isExpirationRequired": False,
                    "maximumDuration": "PT8H",
                }
            ],
        }
    ],
    "assignments": [
        {
            "id": "assign-ga",
            "policyId": "policy-ga",
            "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
            "scopeId": "/",
            "scopeType": "DirectoryRole",
        }
    ],
}
