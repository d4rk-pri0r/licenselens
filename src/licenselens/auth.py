"""Authentication helpers (device code / client credentials / Azure CLI)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from licenselens.errors import AuthConfigError, AuthError

# Default public client used only when --client-id is omitted for device code.
# Customers should prefer their own app registration (see docs/app-registration.md).
DEFAULT_PUBLIC_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft Graph PowerShell


class AuthMode(StrEnum):
    DEVICE_CODE = "device_code"
    CLIENT_SECRET = "client_secret"
    CERTIFICATE = "certificate"
    AZURE_CLI = "azure_cli"
    DRY_RUN = "dry_run"
    OIDC = "oidc"


GRAPH_SCOPE = "https://graph.microsoft.com/.default"

# Power BI / Fabric admin REST is a separate resource from Microsoft Graph.
POWERBI_ADMIN_SCOPE = "https://analysis.windows.net/powerbi/api/.default"

REQUIRED_GRAPH_APP_PERMISSIONS: tuple[str, ...] = (
    "AccessReview.Read.All",
    "Application.Read.All",
    "AuditLog.Read.All",
    "DelegatedPermissionGrant.Read.All",
    "DeviceManagementApps.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "Directory.Read.All",
    "DlpPolicy.Read.All",
    "Domain.Read.All",
    "eDiscovery.Read.All",
    "EntitlementManagement.Read.All",
    "IdentityRiskyServicePrincipal.Read.All",
    "Organization.Read.All",
    "Policy.Read.All",
    "RoleManagement.Read.Directory",
    "SecurityAlert.Read.All",
    "SecurityEvents.Read.All",
    "SecurityIncident.Read.All",
    "User.Read.All",
)

# Power BI admin REST application permissions (separate API resource).
REQUIRED_POWERBI_APP_PERMISSIONS: tuple[str, ...] = ("Tenant.Read.All",)


@dataclass
class AuthContext:
    """Auth context passed to collectors and the Graph client."""

    mode: AuthMode
    tenant_id: str | None = None
    client_id: str | None = None
    credential: Any | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def has_credentials(self) -> bool:
        return self.credential is not None and self.mode != AuthMode.DRY_RUN


def _env(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def resolve_auth_inputs(
    *,
    mode: AuthMode,
    tenant_id: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    certificate_path: str | None = None,
    certificate_thumbprint: str | None = None,
) -> tuple[str | None, str | None, str | None, str | None, str | None]:
    """Merge CLI options with standard Azure environment variables."""
    tid = tenant_id or _env("AZURE_TENANT_ID")
    cid = client_id or _env("AZURE_CLIENT_ID")
    secret = client_secret or _env("AZURE_CLIENT_SECRET")
    cert_path = certificate_path or _env("AZURE_CLIENT_CERTIFICATE_PATH")
    cert_thumb = certificate_thumbprint or _env("AZURE_CLIENT_CERT_THUMBPRINT")
    return tid, cid, secret, cert_path, cert_thumb


def _fetch_github_oidc_token() -> str | None:
    """Fetch a GitHub Actions OIDC token via the standard token exchange.

    Uses the ACTIONS_ID_TOKEN_REQUEST_URL / ACTIONS_ID_TOKEN_REQUEST_TOKEN
    environment variables that GitHub Actions injects into the job runtime.
    Returns None when the runtime env is not present (e.g. not running in
    GitHub Actions).
    """
    request_url = _env("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = _env("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not request_url or not request_token:
        return None

    import urllib.request

    req = urllib.request.Request(
        request_url,
        headers={"Authorization": f"Bearer {request_token}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:  # noqa: S310 - trusted Actions runtime URL
        payload = resp.read()
    import json

    data = json.loads(payload)
    return data.get("value")


def build_credential(
    mode: AuthMode,
    *,
    tenant_id: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    oidc_token: str | None = None,
    certificate_path: str | None = None,
    certificate_thumbprint: str | None = None,
) -> Any:
    """Build an azure-identity credential for the requested mode."""
    if mode == AuthMode.DRY_RUN:
        return None

    try:
        from azure.identity import (
            AzureCliCredential,
            ClientAssertionCredential,
            ClientCertificateCredential,
            ClientSecretCredential,
            DeviceCodeCredential,
        )
    except ImportError as exc:  # pragma: no cover
        raise AuthConfigError(
            "azure-identity is required for live authentication. "
            "Install with: pip install 'licenselens'"
        ) from exc

    if mode == AuthMode.CERTIFICATE:
        if not tenant_id or not client_id or not certificate_path:
            raise AuthConfigError(
                "Certificate auth requires tenant id, client id, and a certificate "
                "path. Pass --tenant-id / --client-id / --certificate (or "
                "AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_CERTIFICATE_PATH)."
            )
        return ClientCertificateCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            certificate_path=certificate_path,
            thumbprint=certificate_thumbprint,
        )

    if mode == AuthMode.AZURE_CLI:
        return AzureCliCredential()

    if mode == AuthMode.OIDC:
        if not tenant_id or not client_id:
            raise AuthConfigError(
                "OIDC (workload-identity federation) auth requires tenant id and "
                "client id. Pass --tenant-id / --client-id or set AZURE_TENANT_ID "
                "and AZURE_CLIENT_ID."
            )
        assertion = oidc_token or _fetch_github_oidc_token()
        if not assertion:
            raise AuthConfigError(
                "OIDC (workload-identity federation) auth requires an OIDC token. "
                "Pass --oidc-token or run inside GitHub Actions so the "
                "ACTIONS_ID_TOKEN_REQUEST_URL / ACTIONS_ID_TOKEN_REQUEST_TOKEN "
                "environment variables are available."
            )
        return ClientAssertionCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            func=lambda: assertion,
        )

    if mode == AuthMode.CLIENT_SECRET:
        if not tenant_id or not client_id or not client_secret:
            raise AuthConfigError(
                "Client-secret auth requires tenant id, client id, and client secret. "
                "Pass --tenant-id / --client-id or set AZURE_TENANT_ID, "
                "AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET. "
                "Run `licenselens setup` for a guided app registration "
                "(docs/app-registration.md)."
            )
        return ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )

    if mode == AuthMode.DEVICE_CODE:
        if not tenant_id:
            raise AuthConfigError(
                "Device-code auth requires a tenant id (--tenant-id or "
                "AZURE_TENANT_ID). Run `licenselens setup` for a guided app "
                "registration (docs/app-registration.md)."
            )
        public_client = client_id or DEFAULT_PUBLIC_CLIENT_ID
        warnings_note = client_id is None
        credential = DeviceCodeCredential(
            tenant_id=tenant_id,
            client_id=public_client,
        )
        # Attach a flag the builder can turn into AuthContext.warnings
        credential._licenselens_used_default_client = warnings_note  # type: ignore[attr-defined]
        return credential

    raise AuthError(f"Unsupported auth mode: {mode}")


def build_auth_context(
    *,
    mode: AuthMode = AuthMode.DRY_RUN,
    tenant_id: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    oidc_token: str | None = None,
    certificate_path: str | None = None,
    certificate_thumbprint: str | None = None,
) -> AuthContext:
    """Build auth context, resolving env vars and constructing credentials."""
    tid, cid, secret, cert_path, cert_thumb = resolve_auth_inputs(
        mode=mode,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        certificate_path=certificate_path,
        certificate_thumbprint=certificate_thumbprint,
    )
    warnings: list[str] = []

    if mode == AuthMode.DRY_RUN:
        return AuthContext(mode=mode, tenant_id=tid, client_id=cid, warnings=warnings)

    credential = build_credential(
        mode,
        tenant_id=tid,
        client_id=cid,
        client_secret=secret,
        oidc_token=oidc_token,
        certificate_path=cert_path,
        certificate_thumbprint=cert_thumb,
    )

    if mode == AuthMode.DEVICE_CODE and getattr(
        credential, "_licenselens_used_default_client", False
    ):
        warnings.append(
            "No --client-id provided for device-code auth; using the Microsoft Graph "
            "PowerShell public client. For production assessments, register your own "
            "app (see docs/app-registration.md)."
        )

    return AuthContext(
        mode=mode,
        tenant_id=tid,
        client_id=cid or (DEFAULT_PUBLIC_CLIENT_ID if mode == AuthMode.DEVICE_CODE else None),
        credential=credential,
        warnings=warnings,
    )
