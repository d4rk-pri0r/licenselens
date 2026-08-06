"""Collect successful sign-in activity (bounded) from Microsoft Graph."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from licenselens.graph import GraphClient


def collect_recent_success_signin_user_ids(
    client: GraphClient,
    *,
    lookback_days: int = 90,
    max_pages: int = 15,
) -> set[str]:
    """Return userIds seen on successful sign-ins within the lookback window.

    Uses a hard page cap to keep scans bounded. May under-count very large
    tenants (conservative: fewer known active users → more dormant candidates).
    """
    start = datetime.now(UTC) - timedelta(days=lookback_days)
    start_s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    path = (
        "/auditLogs/signIns"
        f"?$select=userId,createdDateTime,status"
        f"&$filter=createdDateTime ge {start_s} and status/errorCode eq 0"
        f"&$top=500"
    )
    rows = client.get_list(path, max_pages=max_pages)
    user_ids: set[str] = set()
    for row in rows:
        uid = row.get("userId")
        if uid:
            user_ids.add(str(uid))
    return user_ids


def collect_directory_objects_by_ids(
    client: GraphClient,
    ids: list[str],
    *,
    chunk_size: int = 20,
) -> dict[str, dict[str, Any]]:
    """Resolve directory objects via POST /directoryObjects/getByIds."""
    resolved: dict[str, dict[str, Any]] = {}
    unique_ids = list(dict.fromkeys(ids))
    for i in range(0, len(unique_ids), chunk_size):
        chunk = unique_ids[i : i + chunk_size]
        payload = client.post(
            "/directoryObjects/getByIds",
            json_body={
                "ids": chunk,
                "types": ["user", "group", "servicePrincipal"],
            },
        )
        for item in payload.get("value") or []:
            if isinstance(item, dict) and item.get("id"):
                resolved[str(item["id"])] = item
    return resolved
