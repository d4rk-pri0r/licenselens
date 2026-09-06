"""Log Analytics Query API client (one allowlisted metering query).

LicenseLens never accepts raw KQL. ``run(query_id)`` looks up text in
``ALLOWED_QUERIES`` (exactly one entry in WS3-A). Silent edits of the query
text fail CI via the pinned SHA-256.

Public endpoint (current host; ``api.loganalytics.io`` remains supported):
https://learn.microsoft.com/azure/azure-monitor/logs/api/access-api
Request format:
https://learn.microsoft.com/azure/azure-monitor/logs/api/request-format
Response shape (tables/columns/rows):
https://learn.microsoft.com/rest/api/logsquery/query/get?view=rest-logsquery-v1
Token scope (client credentials): ``https://api.loganalytics.io/.default``.
"""

from __future__ import annotations

import time
from typing import Any, Final

import httpx

from licenselens.auth import AuthContext
from licenselens.cloud_endpoints import CloudEndpoints, UnsupportedCloudError, endpoints_for
from licenselens.collectors.contracts import CloudEnvironment
from licenselens.errors import AuthError, GraphError
from licenselens.http_retry import retry_delay, should_retry

__all__ = [
    "ALLOWED_QUERIES",
    "USAGE_QUERY_ID",
    "USAGE_QUERY_SHA256",
    "USAGE_QUERY_TEXT",
    "LogAnalyticsQueryClient",
    "UnknownQueryIdError",
]

USAGE_QUERY_ID: Final = "usage_by_datatype_7d"
USAGE_QUERY_TEXT: Final = (
    "Usage\n"
    "| where TimeGenerated > ago(7d)\n"
    "| summarize total_mb = sum(Quantity), last_seen = max(TimeGenerated), "
    "rows = count() by DataType\n"
    "| order by DataType asc"
)
USAGE_QUERY_SHA256: Final = "e90cbeac401d946d9f9576748dea5610bc298c14e9ed1673f26bc8e16b0d50ef"
ALLOWED_QUERIES: Final[dict[str, str]] = {USAGE_QUERY_ID: USAGE_QUERY_TEXT}


class UnknownQueryIdError(ValueError):
    """Raised when ``run`` is given an id that is not in ``ALLOWED_QUERIES``."""


class LogAnalyticsQueryClient:
    """POST-only client for the Azure Monitor Logs query API."""

    def __init__(
        self,
        auth: AuthContext,
        *,
        cloud: CloudEnvironment = CloudEnvironment.PUBLIC,
        timeout: float = 60.0,
        base_url: str | None = None,
        max_retries: int = 4,
        sleep: Any = time.sleep,
    ) -> None:
        if auth.credential is None:
            raise AuthError("Log Analytics query client requires credentials.")
        self._auth = auth
        self._cloud = cloud
        self._endpoints: CloudEndpoints = endpoints_for(cloud)
        if not self._endpoints.la_query_supported:
            raise UnsupportedCloudError(cloud=cloud, service="log_analytics_query")
        self._base_url = (base_url or self._endpoints.la_query_base).rstrip("/")
        self._max_retries = max_retries
        self._sleep = sleep
        self._http = httpx.Client(timeout=timeout)
        self._token: str | None = None

    @property
    def cloud(self) -> CloudEnvironment:
        return self._cloud

    @property
    def la_query_scope(self) -> str:
        return self._endpoints.la_query_scope

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> LogAnalyticsQueryClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _token_value(self) -> str:
        if self._token:
            return self._token
        try:
            token = self._auth.credential.get_token(self.la_query_scope)
        except Exception as exc:  # noqa: BLE001
            raise AuthError(
                f"Failed to acquire a Log Analytics Query token: {exc}. "
                "Grant Log Analytics Reader (Data.Read) on the workspace."
            ) from exc
        self._token = token.token
        return self._token

    def run(
        self,
        query_id: str,
        *,
        workspace_customer_id: str,
        timespan: str = "P7D",
    ) -> dict[str, dict[str, Any]]:
        """Execute one allowlisted query. There is no raw-query parameter."""
        query_text = ALLOWED_QUERIES.get(query_id)
        if query_text is None:
            raise UnknownQueryIdError(query_id)
        url = f"{self._base_url}/v1/workspaces/{workspace_customer_id}/query"
        body = {"query": query_text, "timespan": timespan}
        data = self._post(url, body)
        return _parse_usage_tables(data)

    def _post(self, url: str, json_body: dict[str, Any]) -> dict[str, Any]:
        for attempt in range(self._max_retries + 1):
            headers = {
                "Authorization": f"Bearer {self._token_value()}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            try:
                response = self._http.post(url, headers=headers, json=json_body)
            except httpx.HTTPError as exc:
                if attempt >= self._max_retries:
                    raise GraphError(f"Log Analytics query network error: {exc}") from exc
                self._sleep(min(2**attempt, 8))
                continue
            if response.status_code == 401 and attempt == 0:
                self._token = None
                continue
            if response.status_code == 401 and attempt > 0:
                raise self._error_for(url, response)
            if should_retry(response.status_code):
                if attempt >= self._max_retries:
                    raise self._error_for(url, response)
                self._sleep(retry_delay(response, attempt))
                continue
            if response.status_code >= 400:
                raise self._error_for(url, response)
            if not response.content:
                return {}
            payload = response.json()
            if not isinstance(payload, dict):
                raise GraphError("Expected JSON object from Log Analytics Query API.")
            return payload
        raise GraphError(f"Log Analytics query failed after retries for {url}")

    def _error_for(self, url: str, response: httpx.Response) -> GraphError:
        detail = (response.text or "")[:300]
        msg = f"Log Analytics Query {response.status_code} for {url}"
        if detail:
            msg = f"{msg} — {detail}"
        if response.status_code in {401, 403}:
            msg += (
                " Grant Log Analytics Reader (or equivalent Data.Read on the "
                "Log Analytics API) on the workspace."
            )
        return GraphError(msg, status_code=response.status_code)


def _parse_usage_tables(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    tables = payload.get("tables") or []
    if not tables or not isinstance(tables[0], dict):
        raise GraphError("Log Analytics Query response had no tables.")
    primary = tables[0]
    columns = primary.get("columns") or []
    names = [str(col.get("name") or "") for col in columns if isinstance(col, dict)]
    index = {name: i for i, name in enumerate(names) if name}
    for required in ("DataType", "total_mb", "rows"):
        if required not in index:
            raise GraphError(f"Log Analytics Query result missing column {required!r}.")
    parsed: dict[str, dict[str, Any]] = {}
    for row in primary.get("rows") or []:
        if not isinstance(row, list):
            continue
        data_type = str(row[index["DataType"]])
        last_seen = None
        if "last_seen" in index and index["last_seen"] < len(row):
            raw = row[index["last_seen"]]
            last_seen = None if raw is None else str(raw)
        parsed[data_type] = {
            "total_mb": float(row[index["total_mb"]] or 0),
            "last_seen": last_seen,
            "rows": int(row[index["rows"]] or 0),
        }
    return parsed
