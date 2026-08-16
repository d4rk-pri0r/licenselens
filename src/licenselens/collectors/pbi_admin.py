"""Power BI / Fabric admin REST collector (Premium capacities + tenant settings).

App-only or Fabric-admin delegated access against the Power BI service API
(``https://api.powerbi.com/v1.0/myorg``). Read-only; no new runtime dependency
(httpx + azure-identity are already used by the Graph client).
"""

from __future__ import annotations

from typing import Any, Final

import httpx

from licenselens.auth import AuthContext, AuthMode
from licenselens.collectors.contracts import CloudEnvironment
from licenselens.errors import AuthError, GraphError

# Power BI service API is a separate resource from Microsoft Graph.
POWERBI_API_SCOPE: Final = "https://analysis.windows.net/powerbi/api/.default"
POWERBI_API_BASE: Final = "https://api.powerbi.com/v1.0/myorg"

CAPACITIES_PATH: Final = "/admin/capacities"
TENANT_SETTINGS_PATH: Final = "/admin/tenantsettings"

# Least-privileged application permission covering both admin endpoints.
POWERBI_REQUIRED_PERMISSIONS: Final = ("Tenant.Read.All",)

__all__ = [
    "POWERBI_API_BASE",
    "POWERBI_API_SCOPE",
    "POWERBI_REQUIRED_PERMISSIONS",
    "DEMO_PBI_CAPACITY_BUNDLE",
    "collect_pbi_capacity_bundle",
]

# Dry-run fixture: one Premium capacity with a single admin.
DEMO_PBI_CAPACITY_BUNDLE: dict[str, Any] = {
    "capacity_count": 1,
    "capacities": [
        {
            "id": "00000000-0000-0000-0000-000000000001",
            "display_name": "Contoso Premium P1",
            "sku": "P1",
            "state": "Active",
            "admin_count": 1,
            "admins": ["capacity-admin@contoso.example"],
        }
    ],
    "tenant_setting_count": 42,
    "total_admin_count": 1,
    "source": "powerbi.admin.rest",
    "direct": True,
    "proxy": False,
}


class PowerBiAdminError(GraphError):
    """Raised when the Power BI admin REST API cannot be read."""


def _token(auth: AuthContext) -> str:
    if auth.credential is None:
        raise AuthError("Power BI admin REST requires an authenticated credential.")
    try:
        return auth.credential.get_token(POWERBI_API_SCOPE).token
    except Exception as exc:  # noqa: BLE001
        raise PowerBiAdminError(f"Failed to acquire Power BI token: {exc}") from exc


def _get_json(auth: AuthContext, path: str, *, timeout: float = 45.0) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {_token(auth)}",
        "Accept": "application/json",
    }
    url = f"{POWERBI_API_BASE}{path}"
    with httpx.Client(timeout=timeout) as http:
        response = http.get(url, headers=headers)
    if response.status_code == 401:
        raise PowerBiAdminError(
            "Power BI admin REST returned 401 — the app needs the Power BI API "
            "permission 'Tenant.Read.All' with admin consent (docs/permissions.md).",
            status_code=401,
        )
    if response.status_code == 403:
        raise PowerBiAdminError(
            "Power BI admin REST returned 403 — admin endpoints require app-only "
            "auth or a signed-in Fabric/Power BI administrator with 'Tenant.Read.All' "
            "(docs/permissions.md).",
            status_code=403,
        )
    if response.status_code >= 400:
        raise PowerBiAdminError(
            f"Power BI admin REST returned {response.status_code} for {path}",
            status_code=response.status_code,
        )
    data = response.json()
    if not isinstance(data, dict):
        raise PowerBiAdminError(f"Unexpected Power BI admin response for {path}")
    return data


def _capacities(payload: dict[str, Any]) -> list[dict[str, Any]]:
    value = payload.get("value")
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _capacity_summary(capacities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for cap in capacities:
        admins = cap.get("admins")
        admin_list = [str(a) for a in admins if a] if isinstance(admins, list) else []
        rows.append(
            {
                "id": str(cap.get("id") or ""),
                "display_name": str(cap.get("displayName") or ""),
                "sku": str(cap.get("sku") or ""),
                "state": str(cap.get("state") or ""),
                "admin_count": len(admin_list),
                "admins": admin_list,
            }
        )
    return rows


def collect_pbi_capacity_bundle(
    auth: AuthContext,
    *,
    cloud: CloudEnvironment = CloudEnvironment.PUBLIC,
) -> dict[str, Any]:
    """Read Premium/Fabric capacities and tenant settings via the admin REST API."""
    del cloud  # Power BI admin REST is public-cloud only for now
    if auth.mode == AuthMode.DRY_RUN or auth.credential is None:
        raise AuthError("Power BI admin REST requires live authentication.")
    capacities_payload = _get_json(auth, CAPACITIES_PATH)
    capacities = _capacity_summary(_capacities(capacities_payload))
    settings_payload = _get_json(auth, TENANT_SETTINGS_PATH)
    settings = settings_payload.get("value")
    setting_count = len(settings) if isinstance(settings, list) else 0
    return {
        "capacity_count": len(capacities),
        "capacities": capacities,
        "tenant_setting_count": setting_count,
        "total_admin_count": sum(int(c.get("admin_count") or 0) for c in capacities),
        "source": "powerbi.admin.rest",
        "direct": True,
        "proxy": False,
    }
