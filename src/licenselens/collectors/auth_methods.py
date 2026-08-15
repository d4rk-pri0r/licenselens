"""Collect authentication methods policy, configurations, and strengths."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.contracts import EvidenceEnvelope
from licenselens.collectors.graph_collect import SupportsGraphReads, collect_graph_operation
from licenselens.graph import GraphClient

__all__ = [
    "DEMO_AUTH_METHODS_BUNDLE",
    "collect_auth_method_configurations",
    "collect_auth_methods_bundle",
    "collect_auth_methods_evidence",
    "collect_auth_methods_policy",
    "collect_auth_strength_policies",
]


def collect_auth_methods_policy(client: GraphClient) -> dict[str, Any]:
    return client.get("/policies/authenticationMethodsPolicy")


def collect_auth_strength_policies(client: GraphClient) -> list[dict[str, Any]]:
    return client.get_list("/policies/authenticationStrengthPolicies", max_pages=20)


def collect_auth_method_configurations(client: GraphClient) -> list[dict[str, Any]]:
    return client.get_list(
        "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations",
        max_pages=20,
    )


def collect_auth_methods_evidence(client: SupportsGraphReads) -> dict[str, EvidenceEnvelope]:
    return {
        "auth_methods_policy": collect_graph_operation(client, "auth_methods_policy"),
        "auth_strength_policies": collect_graph_operation(client, "auth_strength_policies"),
        "auth_method_configurations": collect_graph_operation(client, "auth_method_configurations"),
    }


def collect_auth_methods_bundle(client: GraphClient) -> dict[str, Any]:
    return {
        "policy": collect_auth_methods_policy(client),
        "strengths": collect_auth_strength_policies(client),
        "configurations": collect_auth_method_configurations(client),
    }


DEMO_AUTH_METHODS_BUNDLE: dict[str, Any] = {
    "policy": {
        "id": "authenticationMethodsPolicy",
        "policyMigrationState": "migrationInProgress",
        "reportSuspiciousActivitySettings": {"state": "default"},
    },
    "strengths": [
        {
            "id": "00000000-0000-0000-0000-000000000004",
            "displayName": "Passwordless MFA",
            "policyType": "builtIn",
        }
    ],
    "configurations": [
        {"id": "microsoftAuthenticator", "state": "enabled"},
        {"id": "sms", "state": "enabled"},
        {"id": "fido2", "state": "disabled"},
    ],
}
