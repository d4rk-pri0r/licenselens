"""Minimal Microsoft Graph HTTP client (pagination + retries)."""

from __future__ import annotations

import time
from typing import Any

import httpx

from licenselens.auth import GRAPH_SCOPE, AuthContext
from licenselens.errors import AuthError, GraphError

DEFAULT_GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class GraphClient:
    """Thin Graph wrapper over httpx + azure-identity token provider."""

    def __init__(
        self,
        auth: AuthContext,
        *,
        base_url: str = DEFAULT_GRAPH_BASE,
        timeout: float = 60.0,
        max_retries: int = 4,
    ) -> None:
        if auth.credential is None:
            raise AuthError("GraphClient requires an AuthContext with a credential.")
        self._auth = auth
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._http = httpx.Client(timeout=timeout)
        self._token: str | None = None

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> GraphClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _get_token(self) -> str:
        if self._token:
            return self._token
        try:
            token = self._auth.credential.get_token(GRAPH_SCOPE)
        except Exception as exc:  # noqa: BLE001 - surface as AuthError
            raise AuthError(f"Failed to acquire Graph token: {exc}") from exc
        self._token = token.token
        return self._token

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        url = path if path.startswith("http") else f"{self._base_url}/{path.lstrip('/')}"
        last_error: Exception | None = None

        for attempt in range(self._max_retries + 1):
            headers = {
                "Authorization": f"Bearer {self._get_token()}",
                "Accept": "application/json",
            }
            if json_body is not None:
                headers["Content-Type"] = "application/json"
            try:
                response = self._http.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    json=json_body,
                )
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt >= self._max_retries:
                    raise GraphError(f"Graph network error: {exc}") from exc
                time.sleep(min(2**attempt, 8))
                continue

            if response.status_code == 401 and attempt == 0:
                # Force token refresh once
                self._token = None
                continue

            if response.status_code == 429 or response.status_code >= 500:
                if attempt >= self._max_retries:
                    raise self._error_from_response(response)
                retry_after = response.headers.get("Retry-After")
                delay = (
                    float(retry_after)
                    if retry_after and retry_after.isdigit()
                    else min(2**attempt, 8)
                )
                time.sleep(delay)
                continue

            if response.status_code >= 400:
                raise self._error_from_response(response)

            if response.status_code == 204 or not response.content:
                return {}
            data = response.json()
            return data

        raise GraphError(f"Graph request failed after retries: {last_error}")

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        data = self.request("GET", path, params=params)
        if not isinstance(data, dict):
            raise GraphError("Expected a JSON object from Graph.")
        return data

    def post(
        self,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        data = self.request("POST", path, params=params, json_body=json_body)
        if not isinstance(data, dict):
            raise GraphError("Expected a JSON object from Graph.")
        return data

    def get_list(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        max_pages: int = 50,
    ) -> list[dict[str, Any]]:
        """GET a collection, following @odata.nextLink up to max_pages."""
        items: list[dict[str, Any]] = []
        next_path: str | None = path
        next_params = params
        pages = 0

        while next_path and pages < max_pages:
            payload = self.get(next_path, params=next_params)
            page_items = payload.get("value") or []
            if isinstance(page_items, list):
                items.extend(item for item in page_items if isinstance(item, dict))
            next_link = payload.get("@odata.nextLink")
            if next_link:
                next_path = str(next_link)
                next_params = None  # nextLink is fully qualified with query
            else:
                next_path = None
            pages += 1

        return items

    @staticmethod
    def _error_from_response(response: httpx.Response) -> GraphError:
        request_id = response.headers.get("request-id") or response.headers.get(
            "x-ms-ags-diagnostic"
        )
        detail = ""
        try:
            body = response.json()
            err = body.get("error") if isinstance(body, dict) else None
            if isinstance(err, dict):
                code = err.get("code") or ""
                message = err.get("message") or ""
                detail = f"{code}: {message}".strip(": ")
        except Exception:  # noqa: BLE001
            detail = (response.text or "")[:300]

        msg = f"Graph {response.status_code} for {response.request.url}"
        if detail:
            msg = f"{msg} — {detail}"
        if response.status_code in {401, 403}:
            msg += (
                " Check app permissions and admin consent "
                "(see docs/app-registration.md and docs/permissions.md)."
            )
        return GraphError(msg, status_code=response.status_code, request_id=request_id)


def fetch_organization_context(client: GraphClient) -> tuple[str | None, str | None]:
    """Return (tenant_id, display_name) from /organization when possible."""
    try:
        rows = client.get_list("/organization")
    except GraphError:
        return None, None
    if not rows:
        return None, None
    org = rows[0]
    return org.get("id"), org.get("displayName")
