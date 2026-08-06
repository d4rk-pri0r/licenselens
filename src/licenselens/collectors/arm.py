"""Minimal Azure Resource Manager (ARM) HTTP client."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from licenselens.auth import AuthContext
from licenselens.errors import AuthError, GraphError

ARM_RESOURCE = "https://management.azure.com"
ARM_SCOPE = f"{ARM_RESOURCE}/.default"
ARM_BASE = ARM_RESOURCE


class ArmClient:
    """Thin ARM wrapper using the same azure-identity credential."""

    def __init__(self, auth: AuthContext, *, timeout: float = 60.0) -> None:
        if auth.credential is None:
            raise AuthError("ARM client requires credentials.")
        self._auth = auth
        self._http = httpx.Client(timeout=timeout)
        self._token: str | None = None

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> ArmClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _token_value(self) -> str:
        if self._token:
            return self._token
        try:
            token = self._auth.credential.get_token(ARM_SCOPE)
        except Exception as exc:  # noqa: BLE001
            raise AuthError(
                f"Failed to acquire Azure Resource Manager token: {exc}. "
                "Ensure the identity can access the target subscription/workspace."
            ) from exc
        self._token = token.token
        return self._token

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = path if path.startswith("http") else f"{ARM_BASE}/{path.lstrip('/')}"
        headers = {
            "Authorization": f"Bearer {self._token_value()}",
            "Accept": "application/json",
        }
        try:
            response = self._http.get(url, headers=headers, params=params)
        except httpx.HTTPError as exc:
            raise GraphError(f"ARM network error: {exc}") from exc
        if response.status_code >= 400:
            detail = (response.text or "")[:400]
            msg = f"ARM {response.status_code} for {url}"
            if detail:
                msg = f"{msg} — {detail}"
            if response.status_code in {401, 403}:
                msg += (
                    " Grant Microsoft Sentinel Reader (or Log Analytics Reader) "
                    "on the workspace and ensure the app has access to the subscription."
                )
            raise GraphError(msg, status_code=response.status_code)
        if not response.content:
            return {}
        data = response.json()
        if not isinstance(data, dict):
            raise GraphError("Expected JSON object from ARM.")
        return data

    def get_list(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        max_pages: int = 30,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        next_url: str | None = None
        pages = 0
        first = True
        while pages < max_pages:
            if first:
                data = self.get(path, params=params)
                first = False
            else:
                assert next_url is not None
                data = self.get(next_url)
            value = data.get("value") or []
            if isinstance(value, list):
                items.extend(v for v in value if isinstance(v, dict))
            next_link = data.get("nextLink")
            if next_link:
                next_url = str(next_link)
                pages += 1
                continue
            break
        return items


def build_workspace_resource_id(
    *,
    subscription_id: str,
    resource_group: str,
    workspace_name: str,
) -> str:
    sub = subscription_id.strip()
    rg = resource_group.strip()
    name = workspace_name.strip()
    return (
        f"/subscriptions/{sub}/resourceGroups/{rg}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{name}"
    )


def normalize_workspace_resource_id(resource_id: str) -> str:
    rid = resource_id.strip()
    if not rid.startswith("/"):
        rid = "/" + rid
    return rid.rstrip("/")


def encode_resource_path(resource_id: str) -> str:
    """Return ARM path without leading slash doubling."""
    rid = normalize_workspace_resource_id(resource_id)
    # Keep slashes; only encode unsafe segments if needed — ARM IDs are path-safe.
    return rid.lstrip("/")


def quote_segment(value: str) -> str:
    return quote(value, safe="")
