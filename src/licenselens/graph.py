"""Minimal Microsoft Graph HTTP client (pagination + retries + cloud roots)."""

from __future__ import annotations

import time
from typing import Any, Final

import httpx

from licenselens.auth import AuthContext, AuthMode
from licenselens.cloud_endpoints import CloudEndpoints, endpoints_for, graph_base_url
from licenselens.collectors.contracts import CloudEnvironment
from licenselens.errors import AuthError, GraphError
from licenselens.graph_list import GraphListResult

DEFAULT_GRAPH_BASE: Final = "https://graph.microsoft.com/v1.0"
_WRITE_METHODS: Final = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_ALLOWED_WRITE_PATH_PREFIXES: Final = frozenset(
    {
        "/directoryObjects/getByIds",
    }
)


class GraphClient:
    """Thin Graph wrapper over httpx + azure-identity token provider."""

    def __init__(
        self,
        auth: AuthContext,
        *,
        cloud: CloudEnvironment = CloudEnvironment.PUBLIC,
        base_url: str | None = None,
        timeout: float = 60.0,
        max_retries: int = 4,
        allow_preview: bool = False,
        sleep: Any = time.sleep,
    ) -> None:
        if auth.credential is None:
            raise AuthError("GraphClient requires an AuthContext with a credential.")
        self._auth = auth
        self._cloud = cloud
        self._endpoints: CloudEndpoints = endpoints_for(cloud)
        self._base_url = (base_url or graph_base_url(cloud)).rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._allow_preview = allow_preview
        self._sleep = sleep
        self._http = httpx.Client(timeout=timeout)
        self._token: str | None = None

    @property
    def cloud(self) -> CloudEnvironment:
        return self._cloud

    @property
    def allow_preview(self) -> bool:
        return self._allow_preview

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def graph_scope(self) -> str:
        return self._endpoints.graph_scope

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
            token = self._auth.credential.get_token(self.graph_scope)
        except Exception as exc:  # noqa: BLE001 - surface as AuthError
            raise AuthError(f"Failed to acquire Graph token: {exc}") from exc
        self._token = token.token
        return self._token

    def _assert_path_allowed(self, method: str, path: str) -> None:
        normalized = path if path.startswith("http") else f"/{path.lstrip('/')}"
        upper = method.upper()
        if "/beta/" in normalized or normalized.startswith("beta/") or "/beta?" in normalized:
            if not self._allow_preview:
                raise GraphError(
                    f"Graph beta endpoint blocked unless allow_preview=True (path={normalized})",
                    status_code=400,
                )
        if upper in _WRITE_METHODS and upper != "POST":
            raise GraphError(
                f"Graph write method {upper} is not permitted (read-only client)",
                status_code=405,
            )
        if upper == "POST":
            relative = normalized
            if relative.startswith("http"):
                # Strip scheme/host for allowlist check
                marker = "/v1.0/"
                beta_marker = "/beta/"
                if marker in relative:
                    relative = "/" + relative.split(marker, 1)[1]
                elif beta_marker in relative:
                    relative = "/" + relative.split(beta_marker, 1)[1]
            path_only = relative.split("?", 1)[0]
            if not any(path_only.startswith(prefix) for prefix in _ALLOWED_WRITE_PATH_PREFIXES):
                raise GraphError(
                    f"Graph POST not allowlisted for read-only client: {path_only}",
                    status_code=405,
                )

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        self._assert_path_allowed(method, path)
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
                self._sleep(min(2**attempt, 8))
                continue

            if response.status_code == 401 and attempt == 0:
                # Force token refresh once
                self._token = None
                continue

            if response.status_code == 401 and attempt > 0:
                raise self._error_from_response(response)

            if response.status_code == 429 or response.status_code >= 500:
                if attempt >= self._max_retries:
                    raise self._error_from_response(response)
                retry_after = response.headers.get("Retry-After")
                delay = (
                    float(retry_after)
                    if retry_after and retry_after.isdigit()
                    else min(2**attempt, 8)
                )
                self._sleep(delay)
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
        return list(self.get_list_result(path, params=params, max_pages=max_pages).items)

    def get_list_result(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        max_pages: int = 50,
    ) -> GraphListResult:
        """GET a collection with explicit truncation metadata."""
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

        return GraphListResult(
            items=tuple(items),
            pages_read=pages,
            max_pages=max_pages,
            next_link_seen=next_path is not None,
        )

    def _error_from_response(self, response: httpx.Response) -> GraphError:
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
            if self._auth.mode == AuthMode.DEVICE_CODE:
                msg += (
                    " Delegated permissions cannot be pre-verified: this "
                    "401/403 names the missing scope — grant it and sign in "
                    "again, or run `licenselens setup` for app-only access "
                    "(see docs/app-registration.md)."
                )
            else:
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
