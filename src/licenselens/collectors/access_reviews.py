"""Collect access review definitions from Microsoft Graph."""

from __future__ import annotations

from typing import Any

from licenselens.graph import GraphClient


def collect_access_review_definitions(client: GraphClient) -> list[dict[str, Any]]:
    """GET /identityGovernance/accessReviews/definitions — all definitions."""
    return client.get_list("/identityGovernance/accessReviews/definitions", max_pages=5)


def collect_access_review_instances(client: GraphClient) -> list[dict[str, Any]]:
    """GET /identityGovernance/accessReviews/definitions?$expand=instances($top=3).

    Returns one row per definition with its most recent review instances
    attached, so evaluators can tell whether a review actually ran.
    """
    return client.get_list(
        "/identityGovernance/accessReviews/definitions",
        params={"$expand": "instances($top=3)"},
        max_pages=5,
    )


# Dry-run: zero access review definitions (never configured)
DEMO_ACCESS_REVIEWS: list[dict[str, Any]] = []

# Dry-run: no review instances ever ran
DEMO_ACCESS_REVIEW_INSTANCES: list[dict[str, Any]] = []
