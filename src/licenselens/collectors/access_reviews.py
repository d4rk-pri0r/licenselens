"""Collect access review definitions from Microsoft Graph."""

from __future__ import annotations

from typing import Any

from licenselens.graph import GraphClient


def collect_access_review_definitions(client: GraphClient) -> list[dict[str, Any]]:
    """GET /identityGovernance/accessReviews/definitions — all definitions."""
    return client.get_list("/identityGovernance/accessReviews/definitions", max_pages=5)


# Dry-run: zero access review definitions (never configured)
DEMO_ACCESS_REVIEWS: list[dict[str, Any]] = []
