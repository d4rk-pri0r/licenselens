"""Discover Log Analytics workspaces that may host Microsoft Sentinel."""

from __future__ import annotations

from typing import Any

from licenselens.auth import AuthContext
from licenselens.collectors.arm import ArmClient
from licenselens.errors import AuthError, GraphError


def list_subscriptions(client: ArmClient) -> list[dict[str, Any]]:
    return client.get_list("subscriptions?api-version=2020-01-01", max_pages=5)


def list_workspaces_in_subscription(
    client: ArmClient,
    subscription_id: str,
) -> list[dict[str, Any]]:
    path = (
        f"subscriptions/{subscription_id}/providers/"
        f"Microsoft.OperationalInsights/workspaces?api-version=2022-10-01"
    )
    return client.get_list(path, max_pages=20)


def workspace_looks_like_sentinel(
    client: ArmClient,
    workspace_resource_id: str,
) -> bool:
    """True if SecurityInsights alertRules API is reachable (even if empty)."""
    rid = workspace_resource_id.lstrip("/")
    path = (
        f"{rid}/providers/Microsoft.SecurityInsights/alertRules"
        f"?api-version=2023-11-01&$top=1"
    )
    try:
        client.get(path)
        return True
    except GraphError as exc:
        # 404 = not onboarded; 403 = no access (treat as not selectable)
        if exc.status_code in {401, 403, 404}:
            return False
        return False


def discover_sentinel_workspaces(
    auth: AuthContext,
    *,
    subscription_id: str | None = None,
    max_subscriptions: int = 10,
) -> list[str]:
    """Return ARM resource IDs of workspaces that respond as Sentinel-capable."""
    found: list[str] = []
    with ArmClient(auth) as client:
        if subscription_id:
            subs = [{"subscriptionId": subscription_id}]
        else:
            try:
                subs = list_subscriptions(client)
            except (AuthError, GraphError):
                return []
        for sub in subs[:max_subscriptions]:
            sid = str(sub.get("subscriptionId") or sub.get("id") or "")
            if "/subscriptions/" in sid:
                sid = sid.rstrip("/").split("/")[-1]
            if not sid:
                continue
            try:
                workspaces = list_workspaces_in_subscription(client, sid)
            except GraphError:
                continue
            for ws in workspaces:
                rid = str(ws.get("id") or "")
                if not rid:
                    continue
                if workspace_looks_like_sentinel(client, rid):
                    found.append(rid if rid.startswith("/") else f"/{rid}")
    return found


def pick_workspace(candidates: list[str]) -> str | None:
    """Return sole candidate, else None (caller must disambiguate)."""
    if len(candidates) == 1:
        return candidates[0]
    return None
