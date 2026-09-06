"""WS3-A: LogAnalyticsQueryClient — one hash-pinned Usage query, no raw KQL."""

from __future__ import annotations

import hashlib
import inspect
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

from licenselens.auth import AuthContext, AuthMode
from licenselens.cloud_endpoints import UnsupportedCloudError
from licenselens.collectors.contracts import CloudEnvironment
from licenselens.collectors.log_analytics_query import (
    ALLOWED_QUERIES,
    USAGE_QUERY_ID,
    USAGE_QUERY_SHA256,
    USAGE_QUERY_TEXT,
    LogAnalyticsQueryClient,
    UnknownQueryIdError,
)
from licenselens.errors import GraphError


def _auth() -> AuthContext:
    credential = MagicMock()
    credential.get_token.return_value = MagicMock(token="test-token")
    return AuthContext(mode=AuthMode.CLIENT_SECRET, tenant_id="t1", credential=credential)


def _client(
    handler, *, max_retries: int | None = None
) -> tuple[LogAnalyticsQueryClient, list[float], AuthContext]:
    auth = _auth()
    sleeps: list[float] = []
    kwargs: dict[str, Any] = {"sleep": sleeps.append}
    if max_retries is not None:
        kwargs["max_retries"] = max_retries
    client = LogAnalyticsQueryClient(auth, **kwargs)
    client._http = httpx.Client(transport=httpx.MockTransport(handler))
    return client, sleeps, auth


_USAGE_PAYLOAD = {
    "tables": [
        {
            "name": "PrimaryResult",
            "columns": [
                {"name": "DataType", "type": "string"},
                {"name": "total_mb", "type": "real"},
                {"name": "last_seen", "type": "datetime"},
                {"name": "rows", "type": "long"},
            ],
            "rows": [
                ["SigninLogs", 12.5, "2026-09-01T00:00:00Z", 40],
                ["AuditLogs", 1.0, None, 4],
            ],
        }
    ]
}


def test_allowlist_is_exactly_one_key() -> None:
    assert list(ALLOWED_QUERIES) == [USAGE_QUERY_ID]


def test_query_hash_pinned() -> None:
    digest = hashlib.sha256(USAGE_QUERY_TEXT.encode()).hexdigest()
    assert digest == USAGE_QUERY_SHA256
    assert ALLOWED_QUERIES[USAGE_QUERY_ID] == USAGE_QUERY_TEXT


def test_run_has_no_raw_query_parameter() -> None:
    params = inspect.signature(LogAnalyticsQueryClient.run).parameters
    assert "query" not in params
    assert "kql" not in params
    assert "text" not in params
    assert "query_id" in params


def test_allowlist_rejects_unknown_id() -> None:
    client, _, _ = _client(
        lambda request: httpx.Response(200, json=_USAGE_PAYLOAD, request=request)
    )
    with pytest.raises(UnknownQueryIdError):
        client.run("not_a_real_query", workspace_customer_id="ws")
    client.close()


def test_parses_usage_rows() -> None:
    client, _, _ = _client(
        lambda request: httpx.Response(200, json=_USAGE_PAYLOAD, request=request)
    )
    parsed = client.run(USAGE_QUERY_ID, workspace_customer_id="ws-guid")
    assert parsed["SigninLogs"]["total_mb"] == 12.5
    assert parsed["SigninLogs"]["rows"] == 40
    assert parsed["AuditLogs"]["last_seen"] is None
    client.close()


def test_429_retry() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(
                429, headers={"Retry-After": "3"}, json={"error": "throttled"}, request=request
            )
        return httpx.Response(200, json=_USAGE_PAYLOAD, request=request)

    client, sleeps, _ = _client(handler)
    assert "SigninLogs" in client.run(USAGE_QUERY_ID, workspace_customer_id="ws")
    assert calls["n"] == 2
    assert sleeps == [3.0]
    client.close()


def test_401_refresh_once() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(401, json={"error": "expired"}, request=request)
        return httpx.Response(200, json=_USAGE_PAYLOAD, request=request)

    client, sleeps, auth = _client(handler)
    client.run(USAGE_QUERY_ID, workspace_customer_id="ws")
    assert auth.credential.get_token.call_count == 2
    assert sleeps == []
    client.close()


def test_china_cloud_unsupported() -> None:
    auth = _auth()
    with pytest.raises(UnsupportedCloudError):
        LogAnalyticsQueryClient(auth, cloud=CloudEnvironment.CHINA)


def test_http_error_sets_status_code() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": "denied"}, request=request)

    client, _, _ = _client(handler)
    with pytest.raises(GraphError) as exc:
        client.run(USAGE_QUERY_ID, workspace_customer_id="ws")
    assert exc.value.status_code == 403
    client.close()
