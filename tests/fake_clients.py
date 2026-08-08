"""In-memory test doubles for GraphClient, ArmClient, and MdeClient.

Each fake replaces the real HTTP layer so collectors can run without network
or a real tenant.  Call ``register_<verb>(path, handler)`` to seed data,
then pass the fake directly to collector functions.

Example::

    from tests.fake_clients import FakeGraphClient, ok, paginated, error

    fake = FakeGraphClient()
    fake.register_list(
        "/subscribedSkus",
        ok({"value": [{"skuPartNumber": "SPE_E5", "servicePlans": []}]}),
    )
    fake.register_list(
        "/identity/conditionalAccess/policies",
        ok({"value": []}),
    )
    skus = collect_subscribed_skus_live(fake)
"""

from __future__ import annotations

from typing import Any, Callable

from licenselens.errors import GraphError

PathHandler = Callable[[str, dict[str, Any] | None], dict[str, Any]]


# ---- canned handlers --------------------------------------------------------


def ok(payload: dict[str, Any]) -> PathHandler:
    """Return a fixed JSON payload regardless of path or params."""

    def _handler(_path: str, _params: dict[str, Any] | None) -> dict[str, Any]:
        return payload

    return _handler


def paginated(*value_pages: list[dict[str, Any]]) -> PathHandler:
    """Multi-page payload driven by @odata.nextLink.

    Each positional arg is the ``value`` array for one page.  The first call
    returns page 0 with a nextLink; subsequent calls follow that link.  When
    there are no more pages, no nextLink is emitted.
    """

    def _handler(path: str, _params: dict[str, Any] | None) -> dict[str, Any]:
        is_next = path.startswith("http")
        idx = 1 if is_next else 0
        if idx >= len(value_pages):
            return {"value": []}
        page: dict[str, Any] = {"value": list(value_pages[idx])}
        if idx + 1 < len(value_pages):
            page["@odata.nextLink"] = f"https://graph.microsoft.com/v1.0/next/{idx + 2}"
        return page

    return _handler


def error(status: int, message: str = "fake error") -> PathHandler:
    """Raise GraphError with the given HTTP status on every call."""

    def _handler(_path: str, _params: dict[str, Any] | None) -> dict[str, Any]:
        raise GraphError(message, status_code=status)

    return _handler


# ---- FakeGraphClient --------------------------------------------------------


class FakeGraphClient:
    """Drop-in replacement for ``GraphClient`` with in-memory routing.

    Routes match by **prefix** — ``/subscribedSkus`` matches
    ``/subscribedSkus?$select=...`` as well.
    """

    def __init__(self) -> None:
        self._get_routes: dict[str, PathHandler] = {}
        self._list_routes: dict[str, PathHandler] = {}
        self._post_routes: dict[str, PathHandler] = {}

    # -- registration ---------------------------------------------------------

    def register_get(self, path_prefix: str, handler: PathHandler) -> None:
        self._get_routes[path_prefix] = handler

    def register_list(self, path_prefix: str, handler: PathHandler) -> None:
        self._list_routes[path_prefix] = handler

    def register_post(self, path_prefix: str, handler: PathHandler) -> None:
        self._post_routes[path_prefix] = handler

    # -- GraphClient-compatible method surface --------------------------------

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        handler = self._find_route(self._get_routes, path)
        if handler is None:
            raise GraphError(
                f"FakeGraphClient: no GET route for {path}", status_code=500
            )
        result = handler(path, params)
        if not isinstance(result, dict):
            raise GraphError("Fake GET handler must return a dict", status_code=500)
        return result

    def get_list(
        self, path: str, *, max_pages: int = 50
    ) -> list[dict[str, Any]]:
        handler = self._find_route(self._list_routes, path)
        if handler is None:
            raise GraphError(
                f"FakeGraphClient: no LIST route for {path}", status_code=500
            )
        items: list[dict[str, Any]] = []
        next_path: str | None = path
        page_num = 0

        while next_path and page_num < max_pages:
            payload = handler(next_path, None)
            if not isinstance(payload, dict):
                raise GraphError("Fake LIST handler must return a dict", status_code=500)
            page_items = payload.get("value") or []
            if isinstance(page_items, list):
                items.extend(item for item in page_items if isinstance(item, dict))
            next_link = payload.get("@odata.nextLink")
            next_path = str(next_link) if next_link else None
            page_num += 1

        return items

    def post(
        self,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        handler = self._find_route(self._post_routes, path)
        if handler is None:
            raise GraphError(
                f"FakeGraphClient: no POST route for {path}", status_code=500
            )
        return handler(path, json_body)

    def request(
        self,
        _method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        raise NotImplementedError("Use register_get/register_list/register_post")

    # -- helpers --------------------------------------------------------------

    def _find_route(
        self, routes: dict[str, PathHandler], path: str
    ) -> PathHandler | None:
        for prefix in sorted(routes, key=len, reverse=True):
            if path.startswith(prefix):
                return routes[prefix]
        return None

    # -- lifecycle stubs ------------------------------------------------------

    def close(self) -> None:
        pass

    def __enter__(self) -> FakeGraphClient:
        return self

    def __exit__(self, *args: object) -> None:
        pass


# ---- FakeArmClient --------------------------------------------------


class FakeArmClient:
    """Drop-in replacement for ``ArmClient`` (Sentinel / workspace collectors)."""

    def __init__(self) -> None:
        self._routes: dict[str, PathHandler] = {}

    def register_get(self, path_prefix: str, handler: PathHandler) -> None:
        self._routes[path_prefix] = handler

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        for prefix in sorted(self._routes, key=len, reverse=True):
            if path.startswith(prefix):
                return self._routes[prefix](path, params)
        raise GraphError(
            f"FakeArmClient: no route for {path}", status_code=500
        )

    def get_list(self, path: str, *, max_pages: int = 30) -> list[dict[str, Any]]:
        handler = None
        for prefix in sorted(self._routes, key=len, reverse=True):
            if path.startswith(prefix):
                handler = self._routes[prefix]
                break
        if handler is None:
            raise GraphError(
                f"FakeArmClient: no route for {path}", status_code=500
            )
        items: list[dict[str, Any]] = []
        next_url: str | None = None
        first = True
        pages = 0
        while pages < max_pages:
            call_path = path if first else (next_url or path)
            payload = handler(call_path, None)
            if not isinstance(payload, dict):
                raise GraphError("Fake ARM handler must return a dict", status_code=500)
            value = payload.get("value") or []
            if isinstance(value, list):
                items.extend(v for v in value if isinstance(v, dict))
            next_link = payload.get("nextLink")
            if next_link:
                next_url = str(next_link)
                pages += 1
                first = False
            else:
                break
        return items

    def close(self) -> None:
        pass

    def __enter__(self) -> FakeArmClient:
        return self

    def __exit__(self, *args: object) -> None:
        pass


# ---- FakeMdeClient ------------------------------------------------


class FakeMdeClient:
    """Drop-in replacement for ``MdeClient``."""

    def __init__(self) -> None:
        self._routes: dict[str, PathHandler] = {}

    def register_get(self, path_prefix: str, handler: PathHandler) -> None:
        self._routes[path_prefix] = handler

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        for prefix in sorted(self._routes, key=len, reverse=True):
            if path.startswith(prefix):
                return self._routes[prefix](path, params)
        raise GraphError(
            f"FakeMdeClient: no route for {path}", status_code=500
        )

    def close(self) -> None:
        pass

    def __enter__(self) -> FakeMdeClient:
        return self

    def __exit__(self, *args: object) -> None:
        pass
