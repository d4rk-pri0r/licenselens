"""Collect Microsoft Defender for Endpoint onboarding signals."""

from __future__ import annotations

from typing import Any

import httpx

from licenselens.auth import AuthContext
from licenselens.cloud_endpoints import CloudEndpoints, UnsupportedCloudError, endpoints_for
from licenselens.collectors.contracts import CloudEnvironment
from licenselens.errors import AuthError, GraphError
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
    ) -> None:
        if auth.credential is None:
            raise AuthError("MDE client requires credentials.")
        self._auth = auth
        self._cloud = cloud
        self._endpoints: CloudEndpoints = endpoints_for(cloud)
        if not self._endpoints.mde_supported:
            raise UnsupportedCloudError(cloud=cloud, service="mde")
        self._base_url = (base_url or self._endpoints.mde_base).rstrip("/")
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
        headers = {
            "Authorization": f"Bearer {self._token_value()}",
            "Accept": "application/json",
        }
        try:
            response = self._http.get(url, headers=headers, params=params)
        except httpx.HTTPError as exc:
            raise GraphError(f"MDE network error: {exc}") from exc
        if response.status_code >= 400:
            detail = (response.text or "")[:300]
            msg = f"MDE API {response.status_code} for {url}"
            if detail:
                msg = f"{msg} — {detail}"
            if response.status_code in {401, 403}:
                msg += (
                    " Grant WindowsDefenderATP application permission "
                    "Machine.Read.All (or equivalent) with admin consent."
                )
            raise GraphError(msg, status_code=response.status_code)
        if not response.content:
            return {}
        data = response.json()
        if not isinstance(data, dict):
            raise GraphError("Expected JSON object from MDE API.")
        return data


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
