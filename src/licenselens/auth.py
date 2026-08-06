"""Authentication helpers (device code / client credentials / Azure CLI).

v0.1a scaffolds the interface. Live token acquisition is wired in a later session.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AuthMode(StrEnum):
    DEVICE_CODE = "device_code"
    CLIENT_SECRET = "client_secret"
    AZURE_CLI = "azure_cli"
    DRY_RUN = "dry_run"


@dataclass(frozen=True)
class AuthContext:
    """Minimal auth context passed to collectors."""

    mode: AuthMode
    tenant_id: str | None = None
    client_id: str | None = None
    # Never log secrets. Client secret stays in env / Key Vault in real runs.
    has_credentials: bool = False


def build_auth_context(
    *,
    mode: AuthMode = AuthMode.DRY_RUN,
    tenant_id: str | None = None,
    client_id: str | None = None,
) -> AuthContext:
    """Build an auth context. Live credential objects arrive in a later milestone."""
    return AuthContext(
        mode=mode,
        tenant_id=tenant_id,
        client_id=client_id,
        has_credentials=mode != AuthMode.DRY_RUN,
    )


# Graph application permissions planned for v0.1 (read-only).
REQUIRED_GRAPH_APP_PERMISSIONS: tuple[str, ...] = (
    "Organization.Read.All",
    "Directory.Read.All",
    "Policy.Read.All",
    "IdentityRiskyUser.Read.All",
    "IdentityRiskEvent.Read.All",
    "Application.Read.All",
    "AuditLog.Read.All",
    "User.Read.All",
    "RoleManagement.Read.Directory",
)
