"""Interactive prompts for first-run scan when flags/env are incomplete."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from licenselens.auth import AuthMode

console = Console()


def _env(name: str) -> str | None:
    value = (os.environ.get(name) or "").strip()
    return value or None


@dataclass
class ScanWizardResult:
    """Resolved scan inputs after optional interactive prompts."""

    live: bool
    auth_mode: AuthMode
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    output_dir: Path = Path("reports")
    open_browser: bool = False
    workspace_resource_id: str | None = None
    run_doctor: bool = False


@dataclass
class QuickstartWizardResult:
    """Resolved quickstart inputs after optional interactive prompts."""

    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    fallback_demo: bool = False


def is_interactive() -> bool:
    """True when stdin is a TTY (safe to prompt)."""
    try:
        return sys.stdin.isatty()
    except Exception:  # noqa: BLE001
        return False


def prompt_for_tenant_id() -> str:
    """Prompt for an Azure tenant id; exit 2 with guidance when left blank.

    Shared by the scan and quickstart wizards (device-code sign-in).
    """
    tid = typer.prompt("Azure tenant ID (Directory ID)", default="").strip() or None
    if not tid:
        console.print(
            "[red]Device-code sign-in needs a tenant ID.[/red] "
            "Find it in Entra ID → Overview → Tenant ID."
        )
        raise typer.Exit(code=2)
    return tid


def _non_tty_live_auth_error() -> None:
    console.print(
        "[red]Missing auth for a live scan.[/red] "
        "Set AZURE_TENANT_ID (and for app-only: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET), "
        "or pass --auth / --tenant-id / --client-id, "
        "or run in an interactive terminal to be prompted."
    )
    raise typer.Exit(code=2)


def _choose(prompt: str, choices: list[tuple[str, str]], *, default: str) -> str:
    """Present numbered choices; return the chosen key."""
    console.print(prompt)
    keys = [k for k, _ in choices]
    for i, (key, label) in enumerate(choices, start=1):
        mark = " (default)" if key == default else ""
        console.print(f"  {i}) {label}{mark}")
    raw = typer.prompt("Choice", default=str(keys.index(default) + 1)).strip()
    if raw.isdigit():
        idx = int(raw)
        if 1 <= idx <= len(choices):
            return choices[idx - 1][0]
    if raw in keys:
        return raw
    lowered = raw.lower()
    for key, label in choices:
        if label.lower().startswith(lowered) or key.startswith(lowered):
            return key
    console.print(f"[yellow]Unrecognized choice {raw!r}; using default.[/yellow]")
    return default


def _parse_auth_flag(auth: str) -> AuthMode:
    key = auth.strip().lower().replace("-", "_")
    mapping = {
        "device": AuthMode.DEVICE_CODE,
        "device_code": AuthMode.DEVICE_CODE,
        "client_secret": AuthMode.CLIENT_SECRET,
        "clientsecret": AuthMode.CLIENT_SECRET,
        "azure_cli": AuthMode.AZURE_CLI,
        "azurecli": AuthMode.AZURE_CLI,
        "cli": AuthMode.AZURE_CLI,
    }
    if key not in mapping:
        console.print(f"[red]Unknown auth mode:[/red] {auth}")
        raise typer.Exit(code=2)
    return mapping[key]


def resolve_scan_inputs(
    *,
    live: bool | None,
    auth: str | None,
    tenant_id: str | None,
    client_id: str | None,
    client_secret: str | None,
    output_dir: Path,
    workspace_resource_id: str | None,
    open_browser: bool = False,
) -> ScanWizardResult:
    """Fill missing scan inputs via prompts when stdin is a TTY.

    Flags and environment values already present are never re-prompted.
    Non-TTY live scans with incomplete auth exit 2 with a clear message.
    """
    interactive = is_interactive()

    # --- mode ---
    if live is None:
        if interactive:
            console.print(
                Panel(
                    "Security License Lens only reads. It never changes policies, "
                    "users, or licenses.",
                    title="Read-only check",
                    border_style="#88b4d8",
                )
            )
            mode_key = _choose(
                "What do you want to scan?",
                [
                    ("demo", "Demo sample data (offline, no sign-in)"),
                    ("live", "My Microsoft tenant (read-only)"),
                ],
                default="demo",
            )
            live_resolved = mode_key == "live"
        else:
            live_resolved = False
    else:
        live_resolved = live

    if not live_resolved:
        return ScanWizardResult(
            live=False,
            auth_mode=AuthMode.DRY_RUN,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            output_dir=output_dir,
            open_browser=open_browser,
            workspace_resource_id=workspace_resource_id,
        )

    # --- auth method ---
    if auth:
        auth_mode = _parse_auth_flag(auth)
    elif client_secret:
        auth_mode = AuthMode.CLIENT_SECRET
    elif interactive:
        choice = _choose(
            "How do you want to sign in?",
            [
                ("device", "Device code (browser sign-in)"),
                ("client_secret", "App registration (client secret)"),
                ("azure_cli", "Azure CLI (`az login`)"),
            ],
            default="device",
        )
        auth_mode = {
            "device": AuthMode.DEVICE_CODE,
            "client_secret": AuthMode.CLIENT_SECRET,
            "azure_cli": AuthMode.AZURE_CLI,
        }[choice]
    else:
        auth_mode = AuthMode.DEVICE_CODE

    # Merge env so we do not re-prompt or false-fail when AZURE_* is set.
    tid = tenant_id or _env("AZURE_TENANT_ID")
    cid = client_id or _env("AZURE_CLIENT_ID")
    secret = client_secret or _env("AZURE_CLIENT_SECRET")

    if auth_mode == AuthMode.CLIENT_SECRET:
        if interactive:
            if not tid:
                tid = typer.prompt("Azure tenant ID (AZURE_TENANT_ID)").strip() or None
            if not cid:
                cid = typer.prompt("App (client) ID (AZURE_CLIENT_ID)").strip() or None
            if not secret:
                secret = (
                    typer.prompt("Client secret (AZURE_CLIENT_SECRET)", hide_input=True).strip()
                    or None
                )
        elif not (tid and cid and secret):
            _non_tty_live_auth_error()
    elif auth_mode == AuthMode.DEVICE_CODE:
        if interactive and not tid:
            tid = prompt_for_tenant_id()
        if interactive and not cid:
            use_default = typer.confirm(
                "Use the default public client for device code? "
                "(OK for a quick try; prefer your own app for production)",
                default=True,
            )
            if not use_default:
                cid = typer.prompt("App (client) ID").strip() or None
        if not interactive and not tid:
            _non_tty_live_auth_error()
    elif auth_mode == AuthMode.AZURE_CLI and interactive:
        console.print("[dim]Using Azure CLI credentials. Run `az login` first if needed.[/dim]")

    out = output_dir
    open_html = open_browser
    workspace = workspace_resource_id
    run_doc = False

    if interactive:
        if str(output_dir) == "reports":
            raw_out = typer.prompt("Output directory", default="reports").strip()
            out = Path(raw_out or "reports")
        if not open_browser:
            open_html = typer.confirm(
                "Open the HTML report in your browser when done?", default=True
            )
        if not workspace and typer.confirm("Include Sentinel workspace checks?", default=False):
            workspace = (
                typer.prompt(
                    "Sentinel workspace ARM resource ID (or leave blank to skip)",
                    default="",
                ).strip()
                or None
            )
        run_doc = typer.confirm("Run a quick preflight (doctor) before scanning?", default=True)

    return ScanWizardResult(
        live=True,
        auth_mode=auth_mode,
        tenant_id=tid,
        client_id=cid,
        client_secret=secret,
        output_dir=out,
        open_browser=open_html,
        workspace_resource_id=workspace,
        run_doctor=run_doc,
    )


def resolve_quickstart_inputs(
    *,
    tenant_id: str | None,
    client_id: str | None,
    client_secret: str | None,
) -> QuickstartWizardResult:
    """Fill missing quickstart auth inputs, mirroring the scan wizard.

    In a TTY, a missing tenant id is prompted (device-code path); an
    explicit client secret also prompts for a missing tenant id / client id.
    Without a TTY and without a tenant id, the result asks the caller to run
    the offline demo instead of hard-failing a fresh install.
    """
    interactive = is_interactive()
    tid = tenant_id or _env("AZURE_TENANT_ID")
    cid = client_id or _env("AZURE_CLIENT_ID")
    secret = client_secret or _env("AZURE_CLIENT_SECRET")

    if secret:
        if interactive:
            if not tid:
                tid = typer.prompt("Azure tenant ID (AZURE_TENANT_ID)").strip() or None
            if not cid:
                cid = typer.prompt("App (client) ID (AZURE_CLIENT_ID)").strip() or None
        return QuickstartWizardResult(tenant_id=tid, client_id=cid, client_secret=secret)

    if not tid:
        if interactive:
            tid = prompt_for_tenant_id()
        else:
            return QuickstartWizardResult(fallback_demo=True)
    if interactive and not cid:
        use_default = typer.confirm(
            "Use the default public client for device code? "
            "(OK for a quick try; prefer your own app for production)",
            default=True,
        )
        if not use_default:
            cid = typer.prompt("App (client) ID").strip() or None
    return QuickstartWizardResult(tenant_id=tid, client_id=cid)
