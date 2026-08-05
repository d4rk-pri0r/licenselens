from licenselens.collectors import workspace_discover as wd
from licenselens.collectors.workspace_discover import pick_workspace
from licenselens.errors import GraphError


class _StubClient:
    """Stand-in for ArmClient: in-memory subscriptions/workspaces."""

    def __init__(self, subscriptions, workspaces, sentinel_ids):
        self._subs = subscriptions
        self._workspaces = workspaces
        self._sentinel_ids = sentinel_ids

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get_list(self, path, *, params=None, max_pages=30):
        if "subscriptions?" in path:
            return list(self._subs)
        return list(self._workspaces)

    def get(self, path, *, params=None):
        if any(sid in path for sid in self._sentinel_ids):
            return {"value": []}
        raise GraphError("not found", status_code=404)


def _workspace(name):
    return {
        "id": (
            "/subscriptions/sub1/resourceGroups/rg/providers/"
            f"Microsoft.OperationalInsights/workspaces/{name}"
        ),
        "name": name,
    }


def test_workspace_looks_like_sentinel_ok():
    client = _StubClient([], [], ["/ws-sentinel"])
    assert wd.workspace_looks_like_sentinel(client, "/subscriptions/s/rg/ws-sentinel")


def test_workspace_looks_like_sentinel_missing():
    client = _StubClient([], [], [])
    assert not wd.workspace_looks_like_sentinel(
        client, "/subscriptions/s/rg/providers/.../workspaces/plain"
    )


def test_discover_filters_non_sentinel(monkeypatch):
    subs = [{"subscriptionId": "sub1"}]
    workspaces = [
        _workspace("sentinel-a"),
        _workspace("plain-b"),
    ]
    sentinel_ids = ["/workspaces/sentinel-a"]
    client = _StubClient(subs, workspaces, sentinel_ids)

    class _CtxFactory:
        def __init__(self, auth):
            self._auth = auth

        def __enter__(self):
            return client

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(wd, "ArmClient", _CtxFactory)
    found = wd.discover_sentinel_workspaces("auth-stub", subscription_id="sub1")
    assert found == [workspaces[0]["id"]]


def test_discover_skips_subscription_without_access(monkeypatch):
    subs = [{"subscriptionId": "sub1"}, {"subscriptionId": "sub2"}]

    class _SelectiveClient(_StubClient):
        def get_list(self, path, *, params=None, max_pages=30):
            if "subscriptions?" in path:
                return list(subs)
            if "sub1" in path:
                raise GraphError("forbidden", status_code=403)
            return [
                {
                    "id": (
                        "/subscriptions/sub2/resourceGroups/rg/providers/"
                        "Microsoft.OperationalInsights/workspaces/sentinel-a"
                    ),
                    "name": "sentinel-a",
                }
            ]

    client = _SelectiveClient(subs, [], ["/workspaces/sentinel-a"])

    class _CtxFactory:
        def __init__(self, auth):
            pass

        def __enter__(self):
            return client

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(wd, "ArmClient", _CtxFactory)
    found = wd.discover_sentinel_workspaces("auth-stub")
    assert found == [
        "/subscriptions/sub2/resourceGroups/rg/providers/"
        "Microsoft.OperationalInsights/workspaces/sentinel-a"
    ]


def test_discover_empty_when_no_subscriptions(monkeypatch):
    class _EmptyClient(_StubClient):
        def get_list(self, path, *, params=None, max_pages=30):
            return []

    class _CtxFactory:
        def __init__(self, auth):
            pass

        def __enter__(self):
            return _EmptyClient([], [], [])

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(wd, "ArmClient", _CtxFactory)
    assert wd.discover_sentinel_workspaces("auth-stub") == []


def test_pick_workspace():
    assert pick_workspace([]) is None
    assert pick_workspace(["only"]) == "only"
    assert pick_workspace(["a", "b"]) is None
