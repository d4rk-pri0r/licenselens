from unittest.mock import MagicMock

import httpx
import pytest

from licenselens.auth import AuthContext, AuthMode
from licenselens.errors import GraphError
from licenselens.graph import GraphClient


class _FakeToken:
    token = "test-token"


def _auth() -> AuthContext:
    cred = MagicMock()
    cred.get_token.return_value = _FakeToken()
    return AuthContext(mode=AuthMode.CLIENT_SECRET, tenant_id="t1", credential=cred)


def test_get_list_follows_next_link(monkeypatch: pytest.MonkeyPatch):
    pages = [
        httpx.Response(
            200,
            json={
                "value": [{"id": "1"}],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/subscribedSkus?$skiptoken=abc",
            },
            request=httpx.Request("GET", "https://graph.microsoft.com/v1.0/subscribedSkus"),
        ),
        httpx.Response(
            200,
            json={"value": [{"id": "2"}]},
            request=httpx.Request(
                "GET",
                "https://graph.microsoft.com/v1.0/subscribedSkus?$skiptoken=abc",
            ),
        ),
    ]
    call = {"i": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        idx = call["i"]
        call["i"] += 1
        return pages[idx]

    transport = httpx.MockTransport(handler)
    client = GraphClient(_auth())
    client._http = httpx.Client(transport=transport)

    items = client.get_list("/subscribedSkus")
    assert [i["id"] for i in items] == ["1", "2"]
    client.close()


def test_graph_403_includes_permission_hint():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={
                "error": {
                    "code": "Authorization_RequestDenied",
                    "message": "Insufficient privileges",
                }
            },
            request=request,
        )

    client = GraphClient(_auth())
    client._http = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(GraphError) as exc:
        client.get("/subscribedSkus")
    assert exc.value.status_code == 403
    assert "permissions" in str(exc.value).lower()
    client.close()


def test_token_acquisition_failure_is_actionable_and_keeps_raw_detail():
    from licenselens.errors import AuthError

    cred = MagicMock()
    cred.get_token.side_effect = RuntimeError("secret expired 700082")
    auth = AuthContext(mode=AuthMode.CLIENT_SECRET, tenant_id="t1", credential=cred)
    client = GraphClient(auth)
    with pytest.raises(AuthError) as exc:
        client.get("/subscribedSkus")
    text = str(exc.value)
    assert "secret expired 700082" not in text  # raw cause never user-facing
    assert "Could not acquire a Microsoft Graph token" in text
    assert "--client-secret" in text  # actionable fix named
    assert "doctor --live" in text
    assert exc.value.detail and "secret expired 700082" in exc.value.detail
    client.close()


def test_network_error_is_actionable_and_keeps_raw_detail():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    client = GraphClient(_auth(), max_retries=0)
    client._http = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(GraphError) as exc:
        client.get("/subscribedSkus")
    text = str(exc.value)
    assert "connection refused" not in text
    assert "network error" in text.lower()
    assert "doctor --live" in text
    assert exc.value.detail and "connection refused" in exc.value.detail
    client.close()
