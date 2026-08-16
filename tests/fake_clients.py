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

from collections.abc import Callable
from typing import Any

from licenselens.collectors.contracts import CloudEnvironment
from licenselens.errors import GraphError
from licenselens.graph import GraphListResult

PathHandler = Callable[[str, dict[str, Any] | None], dict[str, Any]]


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
    state = {"calls": 0}

    def _handler(path: str, _params: dict[str, Any] | None) -> dict[str, Any]:
        is_next = path.startswith("http")
        if is_next:
            # Extract page index from synthetic next link when present
            idx = state["calls"]
        else:
            idx = 0
            state["calls"] = 0
        if idx >= len(value_pages):
            return {"value": []}
        page: dict[str, Any] = {"value": list(value_pages[idx])}
        if idx + 1 < len(value_pages):
            page["@odata.nextLink"] = f"https://graph.microsoft.com/v1.0/next/{idx + 1}"
        state["calls"] = idx + 1
        return page

    return _handler


def error(status: int, message: str = "fake error") -> PathHandler:
    """Raise GraphError with the given HTTP status on every call."""

    def _handler(_path: str, _params: dict[str, Any] | None) -> dict[str, Any]:
        raise GraphError(message, status_code=status)

    return _handler


class FakeGraphClient:
    """Drop-in replacement for ``GraphClient`` with in-memory routing.

    Routes match by **prefix** — ``/subscribedSkus`` matches
    ``/subscribedSkus?$select=...`` as well.
    """

    def __init__(
        self,
        *,
        cloud: CloudEnvironment = CloudEnvironment.PUBLIC,
        allow_preview: bool = False,
        base_url: str = "https://graph.microsoft.com/v1.0",
    ) -> None:
        self.cloud = cloud
        self.allow_preview = allow_preview
        self.base_url = base_url
        self._get_routes: dict[str, PathHandler] = {}
        self._list_routes: dict[str, PathHandler] = {}
        self._post_routes: dict[str, PathHandler] = {}

    def register_get(self, path_prefix: str, handler: PathHandler) -> None:
        self._get_routes[path_prefix] = handler

    def register_list(self, path_prefix: str, handler: PathHandler) -> None:
        self._list_routes[path_prefix] = handler

    def register_post(self, path_prefix: str, handler: PathHandler) -> None:
        self._post_routes[path_prefix] = handler

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._is_beta(path) and not self.allow_preview:
            raise GraphError(
                f"Graph beta endpoint blocked unless allow_preview=True (path={path})",
                status_code=400,
            )
        handler = self._find_route(self._get_routes, path)
        if handler is None:
            # Fall back to list routes for single-resource GETs registered as list
            handler = self._find_route(self._list_routes, path)
        if handler is None:
            raise GraphError(f"FakeGraphClient: no GET route for {path}", status_code=500)
        result = handler(path, params)
        if not isinstance(result, dict):
            raise GraphError("Fake GET handler must return a dict", status_code=500)
        return result

    def get_list(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        max_pages: int = 50,
    ) -> list[dict[str, Any]]:
        return list(self.get_list_result(path, params=params, max_pages=max_pages).items)

    def get_list_result(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        max_pages: int = 50,
    ) -> GraphListResult:
        if self._is_beta(path) and not self.allow_preview:
            raise GraphError(
                f"Graph beta endpoint blocked unless allow_preview=True (path={path})",
                status_code=400,
            )
        handler = self._find_route(self._list_routes, path)
        if handler is None:
            raise GraphError(f"FakeGraphClient: no LIST route for {path}", status_code=500)
        items: list[dict[str, Any]] = []
        next_path: str | None = path
        next_params = params
        page_num = 0

        while next_path and page_num < max_pages:
            payload = handler(next_path, next_params)
            if not isinstance(payload, dict):
                raise GraphError("Fake LIST handler must return a dict", status_code=500)
            page_items = payload.get("value") or []
            if isinstance(page_items, list):
                items.extend(item for item in page_items if isinstance(item, dict))
            next_link = payload.get("@odata.nextLink")
            next_path = str(next_link) if next_link else None
            next_params = None
            page_num += 1

        return GraphListResult(
            items=tuple(items),
            pages_read=page_num,
            max_pages=max_pages,
            next_link_seen=next_path is not None,
        )

    def post(
        self,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        handler = self._find_route(self._post_routes, path)
        if handler is None:
            raise GraphError(f"FakeGraphClient: no POST route for {path}", status_code=500)
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

    def _find_route(self, routes: dict[str, PathHandler], path: str) -> PathHandler | None:
        for prefix in sorted(routes, key=len, reverse=True):
            if path.startswith(prefix):
                return routes[prefix]
        return None

    @staticmethod
    def _is_beta(path: str) -> bool:
        return "/beta/" in path or path.startswith("beta/")

    def close(self) -> None:
        pass

    def __enter__(self) -> FakeGraphClient:
        return self

    def __exit__(self, *args: object) -> None:
        pass


class FakeArmClient:
    """Drop-in replacement for ``ArmClient`` (Sentinel / workspace collectors)."""

    def __init__(self, *, cloud: CloudEnvironment = CloudEnvironment.PUBLIC) -> None:
        self.cloud = cloud
        self._routes: dict[str, PathHandler] = {}

    def register_get(self, path_prefix: str, handler: PathHandler) -> None:
        self._routes[path_prefix] = handler

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        for prefix in sorted(self._routes, key=len, reverse=True):
            if path.startswith(prefix):
                return self._routes[prefix](path, params)
        raise GraphError(f"FakeArmClient: no route for {path}", status_code=500)

    def get_list(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        max_pages: int = 30,
    ) -> list[dict[str, Any]]:
        handler = None
        for prefix in sorted(self._routes, key=len, reverse=True):
            if path.startswith(prefix):
                handler = self._routes[prefix]
                break
        if handler is None:
            raise GraphError(f"FakeArmClient: no route for {path}", status_code=500)
        items: list[dict[str, Any]] = []
        next_url: str | None = None
        first = True
        pages = 0
        while pages < max_pages:
            call_path = path if first else (next_url or path)
            payload = handler(call_path, params if first else None)
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


class FakeMdeClient:
    """Drop-in replacement for ``MdeClient``."""

    def __init__(self, *, cloud: CloudEnvironment = CloudEnvironment.PUBLIC) -> None:
        self.cloud = cloud
        self._routes: dict[str, PathHandler] = {}

    def register_get(self, path_prefix: str, handler: PathHandler) -> None:
        self._routes[path_prefix] = handler

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        for prefix in sorted(self._routes, key=len, reverse=True):
            if path.startswith(prefix):
                return self._routes[prefix](path, params)
        raise GraphError(f"FakeMdeClient: no route for {path}", status_code=500)

    def close(self) -> None:
        pass

    def __enter__(self) -> FakeMdeClient:
        return self

    def __exit__(self, *args: object) -> None:
        pass


class FixturePsRunner:
    """``ProcessRunner`` that replays the PowerShell bridge from a fixture.

    Reads the adapter name out of the stdin request JSON and returns the
    matching fixture payload as a successful bridge response, so the real
    ``map_process_result`` → ``normalize_adapter_payload`` path runs unchanged.
    """

    def __init__(self, payloads: dict[str, Any]) -> None:
        self._payloads = payloads
        self.calls: list[str] = []

    def run(
        self,
        argv: list[str],
        *,
        stdin: bytes,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
        cwd: Any,
        env: Any,
    ) -> Any:
        import json as _json

        from licenselens.collectors.powershell_process import BridgeProcessResult

        request = _json.loads(stdin.decode("utf-8"))
        adapter = str(request.get("adapter") or "")
        self.calls.append(adapter)
        data = self._payloads.get(adapter)
        body: dict[str, Any] = {
            "protocol_version": "1.0",
            "ok": data is not None,
            "adapter": adapter,
            "module_version": "1.0.0",
            "cloud": "public",
            "data": data,
            "error": (
                None
                if data is not None
                else {"code": "module_missing", "message": f"no fixture for {adapter!r}"}
            ),
        }
        raw = _json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return BridgeProcessResult(
            exit_code=0,
            stdout=raw,
            stderr=b"",
            timed_out=False,
            stdout_truncated=False,
            stderr_truncated=False,
        )


class ReplayClients:
    """Fake clients + seam payloads built from a golden-tenant fixture JSON."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.graph = _graph_client_from_fixture(payload, allow_preview=False)
        self.graph_preview = _graph_client_from_fixture(payload, allow_preview=True)
        self.arm = _arm_client_from_fixture(payload)
        self.mde = _mde_client_from_fixture(payload)
        self.ps_runner = FixturePsRunner(dict(payload.get("powershell") or {}))
        self.dns_evidence = dict(payload.get("dns") or {})
        self.pbi_bundle = dict(payload.get("pbi") or {})


def _graph_client_from_fixture(payload: dict[str, Any], *, allow_preview: bool) -> FakeGraphClient:
    fake = FakeGraphClient(allow_preview=allow_preview)
    graph = payload.get("graph") or {}
    for method in ("list", "get", "post"):
        routes = graph.get(method) or {}
        for path, body in routes.items():
            if method == "list":
                fake.register_list(path, ok(body))
            elif method == "get":
                fake.register_get(path, ok(body))
            else:
                fake.register_post(path, ok(body))
    return fake


def _arm_client_from_fixture(payload: dict[str, Any]) -> FakeArmClient:
    fake = FakeArmClient()
    for path, body in (payload.get("arm") or {}).items():
        fake.register_get(path, ok(body))
    return fake


def _mde_client_from_fixture(payload: dict[str, Any]) -> FakeMdeClient:
    fake = FakeMdeClient()
    for path, body in (payload.get("mde") or {}).items():
        fake.register_get(path, ok(body))
    return fake


def build_replay_clients(payload: dict[str, Any]) -> ReplayClients:
    """Build the fake client bundle for a golden-tenant fixture payload."""
    return ReplayClients(payload)


def wire_golden_seams(monkeypatch: Any, replay: ReplayClients) -> None:
    """Monkeypatch every non-Graph live-collection seam to the replay bundle.

    Graph collectors flow through ``ctx.client`` (the ``ReplayClients.graph``
    fake, injected by patching ``engine.runner.GraphClient``). ARM, MDE,
    PowerShell-bridge, DNS, and Power BI each have their own module-level seam,
    patched here so the *real* collector code runs against fixture data.
    """
    from pathlib import Path

    from licenselens.collectors import mde as _mde
    from licenselens.collectors import mde_health as _mde_health

    # Graph: the live branch reads the class off this module at call time.
    monkeypatch.setattr(
        "licenselens.engine.runner.GraphClient",
        lambda _auth, **_kw: replay.graph,
    )
    # Preview (beta) client for Insider Risk Management.
    monkeypatch.setattr(
        "licenselens.collectors.runtime_collect_endpoint._preview_client",
        lambda _ctx, _base: replay.graph_preview,
    )
    # ARM: sentinel bundle + extended + defender pricings each bind ``ArmClient``.
    monkeypatch.setattr(
        "licenselens.collectors.sentinel.ArmClient",
        lambda _auth, **_kw: replay.arm,
    )
    monkeypatch.setattr(
        "licenselens.collectors.sentinel_extended.ArmClient",
        lambda _auth, **_kw: replay.arm,
    )
    monkeypatch.setattr(
        "licenselens.collectors.arm.ArmClient",
        lambda _auth, **_kw: replay.arm,
    )
    # MDE: wrap the real collectors with a FakeMdeClient (MdeClient.__init__
    # requires a credential, which the fake scan does not provide).
    monkeypatch.setattr(
        "licenselens.collectors.runtime.collect_mde_machine_summary",
        lambda _auth: _mde.collect_mde_machine_summary(_auth, client=replay.mde),
    )
    monkeypatch.setattr(
        "licenselens.collectors.runtime_collect_endpoint.collect_mde_health_summary",
        lambda _auth: _mde_health.collect_mde_health_summary(_auth, client=replay.mde),
    )
    # PowerShell bridge: replay responses from the fixture without a real pwsh.
    monkeypatch.setattr(
        "licenselens.collectors.powershell.BoundedProcessRunner",
        lambda: replay.ps_runner,
    )
    monkeypatch.setattr(
        "licenselens.collectors.powershell.find_powershell_executable",
        lambda: Path("/usr/bin/pwsh"),
    )
    # DNS: serve checked-in evidence; the live _domain_state path is broken
    # (SpfState is a slots dataclass, so `spf.__dict__` fails) — out of scope here.
    monkeypatch.setattr(
        "licenselens.collectors.runtime_collect_mail.collect_dns_evidence",
        lambda _domains, _resolver: replay.dns_evidence,
    )
    # Power BI admin REST is a separate resource; serve the fixture bundle.
    monkeypatch.setattr(
        "licenselens.collectors.runtime_collect_endpoint.collect_pbi_capacity_bundle",
        lambda _auth: replay.pbi_bundle,
    )
    # Sentinel auto-discovery stays off unless explicitly requested.
    monkeypatch.setattr(
        "licenselens.collectors.workspace_discover.discover_sentinel_workspaces",
        lambda _auth: [],
    )
