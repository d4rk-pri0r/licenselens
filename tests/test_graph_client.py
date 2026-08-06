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
