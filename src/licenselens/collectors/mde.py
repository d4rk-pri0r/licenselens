"""Collect Microsoft Defender for Endpoint onboarding signals."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from licenselens.auth import AuthContext
from licenselens.cloud_endpoints import CloudEndpoints, UnsupportedCloudError, endpoints_for
from licenselens.collectors.contracts import CloudEnvironment
from licenselens.collectors.device_hash import hash_device_label
from licenselens.errors import AuthError, GraphError
from licenselens.http_retry import retry_delay, should_retry
from licenselens.models import SubscribedSku

MDE_RESOURCE = "https://api.securitycenter.microsoft.com"
MDE_SCOPE = f"{MDE_RESOURCE}/.default"
MDE_BASE = f"{MDE_RESOURCE}/api"

MDE_PLAN_HINTS: tuple[str, ...] = (
    "DEFENDER_ENDPOINT_P2",
    "MDATP_XPLAT",
    "WINDEFATP",
    "MICROSOFTDEFENDERATP",
)


def mde_licensed_units(skus: list[SubscribedSku]) -> int | None:
    """Best-effort prepaid/enabled units for MDE-related plans."""
    total = 0
    found = False
    for sku in skus:
        for plan in sku.service_plans:
            name = (plan.service_plan_name or "").upper()
            if any(h in name for h in MDE_PLAN_HINTS):
                found = True
                if sku.prepaid_units is not None:
                    total += int(sku.prepaid_units)
                break
    if not found:
        return None
    return total


class MdeClient:
    """Minimal client for Defender for Endpoint API."""

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
            raise AuthError("MDE client requires credentials.")
        self._auth = auth
        self._cloud = cloud
        self._endpoints: CloudEndpoints = endpoints_for(cloud)
        if not self._endpoints.mde_supported:
            raise UnsupportedCloudError(cloud=cloud, service="mde")
        self._base_url = (base_url or self._endpoints.mde_base).rstrip("/")
        self._max_retries = max_retries
        self._sleep = sleep
        self._http = httpx.Client(timeout=timeout)
        self._token: str | None = None

    @property
    def cloud(self) -> CloudEnvironment:
        return self._cloud

    @property
    def mde_scope(self) -> str:
        return self._endpoints.mde_scope

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> MdeClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _token_value(self) -> str:
        if self._token:
            return self._token
        try:
            token = self._auth.credential.get_token(self.mde_scope)
        except Exception as exc:  # noqa: BLE001
            raise AuthError(
                f"Failed to acquire Defender for Endpoint token: {exc}. "
                "Grant application permission to WindowsDefenderATP / "
                "Machine.Read.All and admin-consent the API."
            ) from exc
        self._token = token.token
        return self._token

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = path if path.startswith("http") else f"{self._base_url}/{path.lstrip('/')}"
        for attempt in range(self._max_retries + 1):
            headers = {
                "Authorization": f"Bearer {self._token_value()}",
                "Accept": "application/json",
            }
            try:
                response = self._http.get(url, headers=headers, params=params)
            except httpx.HTTPError as exc:
                if attempt >= self._max_retries:
                    raise GraphError(f"MDE network error: {exc}") from exc
                self._sleep(min(2**attempt, 8))
                continue
            if response.status_code == 401 and attempt == 0:
                # Force one token refresh (mirrors GraphClient).
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
            data = response.json()
            if not isinstance(data, dict):
                raise GraphError("Expected JSON object from MDE API.")
            return data
        raise GraphError(f"MDE request failed after retries for {url}")

    def _error_for(self, url: str, response: httpx.Response) -> GraphError:
        detail = (response.text or "")[:300]
        msg = f"MDE API {response.status_code} for {url}"
        if detail:
            msg = f"{msg} — {detail}"
        if response.status_code in {401, 403}:
            msg += (
                " Grant WindowsDefenderATP application permission "
                "Machine.Read.All (or equivalent) with admin consent."
            )
        return GraphError(msg, status_code=response.status_code)


def collect_mde_machine_summary(
    auth: AuthContext,
    *,
    cloud: CloudEnvironment = CloudEnvironment.PUBLIC,
    client: MdeClient | None = None,
) -> dict[str, Any]:
    """Return onboarded machine counts from MDE API (bounded sample)."""
    owns = client is None
    mde = client if client is not None else MdeClient(auth, cloud=cloud)
    try:
        try:
            data = mde.get("/machines", params={"$top": "1", "$count": "true"})
            count = data.get("@odata.count")
            if count is not None:
                return {
                    "onboarded_machines": int(count),
                    "sample_size": 1,
                    "count_method": "odata_count",
                }
        except GraphError:
            pass

        total = 0
        top = 200
        skip = 0
        pages = 0
        max_pages = 10
        while pages < max_pages:
            data = mde.get("/machines", params={"$top": str(top), "$skip": str(skip)})
            value = data.get("value") or []
            if not isinstance(value, list) or not value:
                break
            total += len(value)
            if len(value) < top:
                break
            skip += top
            pages += 1
        truncated = pages >= max_pages
        return {
            "onboarded_machines": total,
            "sample_size": total,
            "count_method": "paged_sample",
            "truncated": truncated,
        }
    finally:
        if owns:
            mde.close()


DEMO_MDE_SUMMARY: dict[str, Any] = {
    "onboarded_machines": 40,
    "sample_size": 40,
    "count_method": "demo",
    "truncated": False,
    "licensed_units": 100,
}

DEMO_MDE_INVENTORY: dict[str, Any] = {
    "machines": [],
    "count": 0,
    "truncated": False,
    "window_days": 30,
    "filter": "lastSeen gt",
}


def collect_mde_machines_inventory(
    auth: AuthContext,
    *,
    cloud: CloudEnvironment = CloudEnvironment.PUBLIC,
    client: MdeClient | None = None,
    now: datetime | None = None,
    max_pages: int = 20,
) -> dict[str, Any]:
    """Return hashed MDE machine inventory for devices seen in the last 30 days."""
    owns = client is None
    mde = client if client is not None else MdeClient(auth, cloud=cloud)
    cutoff = (now or datetime.now(UTC)).astimezone(UTC) - timedelta(days=30)
    filt = f"lastSeen gt {cutoff.strftime('%Y-%m-%d')}Z"
    try:
        machines: list[dict[str, Any]] = []
        pages = 0
        path = "/machines"
        params: dict[str, Any] = {
            "$select": (
                "id,aadDeviceId,computerDnsName,osPlatform,healthStatus,onboardingStatus,lastSeen"
            ),
            "$top": "1000",
            "$filter": filt,
        }
        while pages < max_pages:
            data = mde.get(path, params=params)
            value = data.get("value") or []
            if not isinstance(value, list):
                break
            for item in value:
                if not isinstance(item, dict):
                    continue
                machines.append(
                    {
                        "id": str(item.get("id") or ""),
                        "aadDeviceId": str(item.get("aadDeviceId") or ""),
                        "computerDnsName_hash": hash_device_label(item.get("computerDnsName")),
                        "osPlatform": item.get("osPlatform"),
                        "healthStatus": item.get("healthStatus"),
                        "onboardingStatus": item.get("onboardingStatus"),
                        "lastSeen": item.get("lastSeen"),
                    }
                )
            nxt = data.get("@odata.nextLink")
            pages += 1
            if not nxt or not isinstance(nxt, str):
                break
            path = nxt
            params = {}
        return {
            "machines": machines,
            "count": len(machines),
            "truncated": pages >= max_pages,
            "window_days": 30,
            "filter": filt,
        }
    finally:
        if owns:
            mde.close()
