"""Pure posture-assessment layer for the MCP surface (no MCP SDK imports).

Success  -> dict identical to ScanResult.model_dump(mode="json")
Failure  -> {"error": {"code": ..., "message": ..., "hint": ...}}
"""

from __future__ import annotations

from datetime import datetime

from licenselens.auth import AuthMode, build_auth_context
from licenselens.engine.runner import run_scan
from licenselens.errors import AuthError, LicenseLensError
from licenselens.graph import GraphError
from licenselens.models import CheckPack, Workload

#: auth values accepted over MCP. Device sign-in needs a TTY and is CLI-only.
LIVE_AUTH_MODES: dict[str, AuthMode] = {
    "client_secret": AuthMode.CLIENT_SECRET,
    "certificate": AuthMode.CERTIFICATE,
    "azure_cli": AuthMode.AZURE_CLI,
    "oidc": AuthMode.OIDC,
}

_LIVE_HINT = (
    "Run `licenselens scan --live` in a terminal for interactive sign-in, or set "
    "AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET and retry with "
    "auth=client_secret."
)

_ENV_CLIENT_SECRET_VARS = ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET")


def _error(code: str, message: str, hint: str) -> dict:
    return {"error": {"code": code, "message": message, "hint": hint}}


def _env_client_secret_ready() -> bool:
    import os

    return all(os.environ.get(var) for var in _ENV_CLIENT_SECRET_VARS)


def _validate_workloads(workloads: list[str] | None) -> list[Workload] | None | dict:
    """Coerce workload names to the enum; return an error envelope on failure."""
    if workloads is None:
        return None
    try:
        return [Workload(w.strip()) for w in workloads]
    except ValueError:
        allowed = ", ".join(w.value for w in Workload)
        return _error(
            "invalid_argument",
            f"Unknown workload(s) in {workloads!r}.",
            f"Allowed workloads: {allowed}.",
        )


def _validate_packs(packs: list[str] | None) -> list[str] | None | dict:
    """Validate pack names against the CheckPack enum; error envelope on failure."""
    if packs is None:
        return None
    try:
        return [CheckPack(p.strip()).value for p in packs]
    except ValueError:
        allowed = ", ".join(p.value for p in CheckPack)
        return _error(
            "invalid_argument",
            f"Unknown pack(s) in {packs!r}.",
            f"Allowed packs: {allowed}.",
        )


def run_assessment(
    *,
    live: bool = False,
    auth: str | None = None,
    tenant_id: str | None = None,
    workloads: list[str] | None = None,
    packs: list[str] | None = None,
    scanned_at: datetime | None = None,  # tests freeze this for byte parity
) -> dict:
    """Run a posture assessment and return the locked ScanResult JSON contract.

    Never raises: every failure mode is a structured ``{"error": {...}}`` envelope
    with ``code`` in ``auth_unavailable | auth_config | invalid_argument |
    scan_failed`` so the MCP host always gets a parseable response.
    """
    # 1. Validate args before touching auth so config errors can't masquerade
    #    as argument errors.
    if auth is not None and auth not in LIVE_AUTH_MODES:
        return _error(
            "invalid_argument",
            f"Unknown auth mode {auth!r}. Device sign-in is not available over MCP "
            "(it requires an interactive terminal).",
            "Use one of: client_secret, certificate, azure_cli, oidc — or run "
            "`licenselens scan --live` in a terminal for device sign-in.",
        )
    validated_workloads = _validate_workloads(workloads)
    if isinstance(validated_workloads, dict):
        return validated_workloads
    validated_packs = _validate_packs(packs)
    if isinstance(validated_packs, dict):
        return validated_packs

    common_kwargs: dict = {
        "workloads": validated_workloads,
        "packs": validated_packs,
        "scanned_at": scanned_at,
    }

    try:
        if not live:
            # Mirror the CLI offline demo exactly: DRY_RUN auth context +
            # dry_run=True scan (profile=None, demo_scenario=None).
            auth_context = build_auth_context(mode=AuthMode.DRY_RUN)
            result = run_scan(
                auth_context,
                dry_run=True,
                profile=None,
                demo_scenario=None,
                **common_kwargs,
            )
            return result.model_dump(mode="json")

        # Live path: default to env-resolved client-secret credentials; never
        # probe `az` implicitly (binary spawn) — azure_cli is explicit-only.
        if auth is None:
            if not _env_client_secret_ready():
                return _error(
                    "auth_unavailable",
                    "Live assessment requested but no usable credentials are "
                    "available in this environment.",
                    _LIVE_HINT,
                )
            mode = AuthMode.CLIENT_SECRET
        else:
            mode = LIVE_AUTH_MODES[auth]

        auth_context = build_auth_context(mode=mode, tenant_id=tenant_id)
        result = run_scan(auth_context, dry_run=False, **common_kwargs)
        return result.model_dump(mode="json")
    except AuthError as exc:  # includes AuthConfigError
        return _error(
            "auth_config",
            str(exc) or "Authentication could not be configured for the live scan.",
            _LIVE_HINT,
        )
    except GraphError as exc:
        return _error(
            "scan_failed",
            f"Microsoft Graph query failed: {exc}",
            "Check network connectivity and credential permissions "
            "(read-only directory scopes; see docs/permissions.md), then retry.",
        )
    except LicenseLensError as exc:
        return _error(
            "scan_failed",
            str(exc) or "The posture scan failed.",
            "Retry the assessment; if it persists, run `licenselens scan` in a "
            "terminal for the full error output.",
        )
    # Unexpected exceptions intentionally propagate: the server layer maps them
    # to a scan_failed envelope so the process never crashes on a tool call.
