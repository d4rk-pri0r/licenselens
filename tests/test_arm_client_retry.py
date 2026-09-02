"""WS0-A: ArmClient retry parity with GraphClient (401 refresh, 429/5xx, Retry-After).

ARM throttling reference: https://learn.microsoft.com/azure/azure-resource-manager/
management/request-limits-and-throttling
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

from licenselens.auth import AuthContext, AuthMode
from licenselens.collectors.arm import ArmClient
from licenselens.errors import GraphError


def _auth() -> AuthContext:
    credential = MagicMock()
    credential.get_token.return_value = MagicMock(token="test-token")
    return AuthContext(mode=AuthMode.CLIENT_SECRET, tenant_id="t1", credential=credential)


def _client(
    handler, *, max_retries: int | None = None
) -> tuple[ArmClient, list[float], AuthContext]:
    auth = _auth()
    sleeps: list[float] = []
    kwargs: dict[str, Any] = {"sleep": sleeps.append}
    if max_retries is not None:
        kwargs["max_retries"] = max_retries
    client = ArmClient(auth, **kwargs)
    client._http = httpx.Client(transport=httpx.MockTransport(handler))
    return client, sleeps, auth


def test_arm_retries_429_then_succeeds() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(
                429, headers={"Retry-After": "2"}, json={"error": "throttled"}, request=request
            )
        return httpx.Response(200, json={"value": [{"id": "1"}]}, request=request)

    client, sleeps, _ = _client(handler)
    result = client.get("/subscriptions/sub-1/resourceGroups/rg")
    assert result == {"value": [{"id": "1"}]}
    assert calls["n"] == 2
    assert sleeps == [2.0]  # Retry-After digits win
    client.close()


def test_arm_refreshes_token_once_on_401() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(401, json={"error": {"message": "expired"}}, request=request)
        return httpx.Response(200, json={"value": []}, request=request)

    client, sleeps, auth = _client(handler)
    assert client.get("/subscriptions/sub-1") == {"value": []}
    assert auth.credential.get_token.call_count == 2  # cached token cleared exactly once
    assert sleeps == []  # 401 refresh does not sleep
    client.close()


def test_arm_second_401_raises_with_rbac_hint() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "invalid"}}, request=request)

    client, sleeps, auth = _client(handler)
    with pytest.raises(GraphError) as exc:
        client.get("/subscriptions/sub-1")
    assert exc.value.status_code == 401
    assert "Microsoft Sentinel Reader" in str(exc.value)  # existing RBAC hint preserved
    assert auth.credential.get_token.call_count == 2  # refreshed once, then raised
    assert sleeps == []
    client.close()


def test_arm_gives_up_after_max_retries_on_503() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, json={"error": {"message": "unavailable"}}, request=request)

    client, sleeps, _ = _client(handler, max_retries=2)
    with pytest.raises(GraphError) as exc:
        client.get("/subscriptions/sub-1")
    assert exc.value.status_code == 503
    assert "ARM 503" in str(exc.value)
    assert calls["n"] == 3  # initial attempt + 2 retries
    assert sleeps == [1.0, 2.0]  # min(2**attempt, 8) backoff
    client.close()


def test_arm_403_raises_immediately_without_retry() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(403, json={"error": {"message": "forbidden"}}, request=request)

    client, sleeps, _ = _client(handler)
    with pytest.raises(GraphError) as exc:
        client.get("/subscriptions/sub-1")
    assert exc.value.status_code == 403
    assert "Microsoft Sentinel Reader" in str(exc.value)
    assert calls["n"] == 1  # no retry on 403
    assert sleeps == []
    client.close()
