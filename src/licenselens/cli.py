"""Security License Lens command-line interface."""

from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from licenselens import __cli_name__, __product_name__, __version__
from licenselens.auth import AuthMode, build_auth_context
from licenselens.batch import run_batch
from licenselens.collectors.arm import build_workspace_resource_id
from licenselens.collectors.workspace_discover import discover_sentinel_workspaces
from licenselens.diff_report import write_diff_report
from licenselens.doctor import run_doctor
from licenselens.engine.loader import load_checks
from licenselens.engine.runner import run_scan
from licenselens.errors import AuthError, GraphError, LicenseLensError
from licenselens.models import Workload
from licenselens.report import write_html_report, write_json_report, write_markdown_report

app = typer.Typer(
    name=__cli_name__,
    help=(
        f"{__product_name__}: detect Microsoft security configuration debt — "
        "capabilities you pay for but leave unused."
    ),
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


class AuthModeOption(StrEnum):
    DEVICE = "device"
    CLIENT_SECRET = "client_secret"
    AZURE_CLI = "azure_cli"


def _to_auth_mode(option: AuthModeOption | None, *, live: bool) -> AuthMode:
    if not live:
        return AuthMode.DRY_RUN
    if option is None:
        return AuthMode.DEVICE_CODE
    return {
        AuthModeOption.DEVICE: AuthMode.DEVICE_CODE,
        AuthModeOption.CLIENT_SECRET: AuthMode.CLIENT_SECRET,
        AuthModeOption.AZURE_CLI: AuthMode.AZURE_CLI,
    }[option]


def _resolve_workspace_resource_id(
    workspace_resource_id: str | None,
    subscription_id: str | None,
    resource_group: str | None,
    workspace_name: str | None,
) -> str | None:
    rid = (workspace_resource_id or os.environ.get("SENTINEL_WORKSPACE_RESOURCE_ID") or "").strip()
    if rid:
        return rid
    sub = (subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID") or "").strip()
    rg = (resource_group or os.environ.get("SENTINEL_RESOURCE_GROUP") or "").strip()
    name = (workspace_name or os.environ.get("SENTINEL_WORKSPACE_NAME") or "").strip()
    if sub and rg and name:
        return build_workspace_resource_id(
            subscription_id=sub,
            resource_group=rg,
            workspace_name=name,
        )
    return None


def _exit_for_scan(result_has_gaps: bool, *, errored: bool = False) -> None:
    if errored:
        raise typer.Exit(code=2)
    if result_has_gaps:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command("version")
def version_cmd() -> None:
    """Print the Security License Lens version."""
    console.print(f"{__product_name__} ({__cli_name__}) {__version__}")


@app.command("checks")
def checks_cmd() -> None:
    """List registered checks from the checks/ tree."""
    checks = load_checks()
    if not checks:
        console.print("[yellow]No checks found.[/yellow]")
        raise typer.Exit(code=0)

    table = Table(title=f"{__product_name__} checks")
    table.add_column("ID")
    table.add_column("Workload")
    table.add_column("Severity")
    table.add_column("Value")
    table.add_column("Title")
    for c in checks:
        table.add_row(
            c.id,
            c.workload.value,
            c.severity.value,
            c.value_impact.value,
            c.title,
        )
    console.print(table)


@app.command("doctor")
def doctor_cmd(
    live: bool = typer.Option(
        False,
        "--live/--dry-run",
        help="Probe a real tenant (default: dry-run message only).",
    ),
    auth: AuthModeOption | None = typer.Option(
        None,
        "--auth",
        help="Live auth mode: device | client_secret | azure_cli.",
    ),
    profile: str = typer.Option(
        "basic",
        "--profile",
        help="Probe depth: basic (core Graph) | full (also MDE API + Sentinel).",
    ),
    tenant_id: str | None = typer.Option(None, "--tenant-id", envvar="AZURE_TENANT_ID"),
    client_id: str | None = typer.Option(None, "--client-id", envvar="AZURE_CLIENT_ID"),
    client_secret: str | None = typer.Option(
        None,
        "--client-secret",
        envvar="AZURE_CLIENT_SECRET",
        help="Client secret (prefer env AZURE_CLIENT_SECRET).",
    ),
    workspace_resource_id: str | None = typer.Option(
        None,
        "--workspace-resource-id",
        help="Sentinel/Log Analytics workspace ARM resource ID.",
    ),
    subscription_id: str | None = typer.Option(
        None,
        "--subscription-id",
        envvar="AZURE_SUBSCRIPTION_ID",
    ),
    resource_group: str | None = typer.Option(
        None,
        "--resource-group",
        envvar="SENTINEL_RESOURCE_GROUP",
    ),
    workspace_name: str | None = typer.Option(
        None,
        "--workspace-name",
        envvar="SENTINEL_WORKSPACE_NAME",
    ),
) -> None:
    """Preflight credentials and core Graph / optional Sentinel permissions."""
    mode = _to_auth_mode(auth, live=live)
    workspace = _resolve_workspace_resource_id(
        workspace_resource_id, subscription_id, resource_group, workspace_name
    )
    try:
        ctx = build_auth_context(
            mode=mode,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        report = run_doctor(ctx, workspace_resource_id=workspace, profile=profile)
    except ValueError as exc:
        console.print(f"[red]Doctor configuration error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except LicenseLensError as exc:
        console.print(f"[red]Doctor failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    for warning in ctx.warnings:
        console.print(f"[yellow]Warning:[/yellow] {warning}")

    table = Table(title=f"{__product_name__} doctor")
    table.add_column("Check")
    table.add_column("OK")
    table.add_column("Detail")
    for item in report.checks:
        table.add_row(item.name, "yes" if item.ok else "no", item.detail)
    console.print(table)

    if report.tenant_display_name or report.tenant_id:
        console.print(
            f"Tenant: {report.tenant_display_name or '—'} "
            f"({report.tenant_id or '—'})"
        )
    if report.sku_count:
        console.print(f"Subscribed SKUs: {report.sku_count}")

    raise typer.Exit(code=0 if report.ok else 2)


@app.command("scan")
def scan_cmd(
    output_dir: Path = typer.Option(
        Path("reports"),
        "--output-dir",
        "-o",
        help="Directory for HTML/JSON/Markdown reports.",
    ),
    workload: list[str] | None = typer.Option(
        None,
        "--workload",
        "-w",
        help="Limit to workload(s): identity, defender, sentinel, purview, endpoint.",
    ),
    live: bool = typer.Option(
        False,
        "--live/--dry-run",
        help="Query a real tenant via Microsoft Graph (default: dry-run demo data).",
    ),
    auth: AuthModeOption | None = typer.Option(
        None,
        "--auth",
        help="Live auth mode: device | client_secret | azure_cli.",
    ),
    tenant_id: str | None = typer.Option(None, "--tenant-id", envvar="AZURE_TENANT_ID"),
    client_id: str | None = typer.Option(None, "--client-id", envvar="AZURE_CLIENT_ID"),
    client_secret: str | None = typer.Option(
        None,
        "--client-secret",
        envvar="AZURE_CLIENT_SECRET",
        help="Client secret (prefer env AZURE_CLIENT_SECRET).",
    ),
    workspace_resource_id: str | None = typer.Option(
        None,
        "--workspace-resource-id",
        help="Sentinel workspace ARM resource ID (required for live Sentinel checks).",
    ),
    subscription_id: str | None = typer.Option(
        None,
        "--subscription-id",
        envvar="AZURE_SUBSCRIPTION_ID",
        help="Azure subscription ID (with --resource-group and --workspace-name).",
    ),
    resource_group: str | None = typer.Option(
        None,
        "--resource-group",
        envvar="SENTINEL_RESOURCE_GROUP",
    ),
    workspace_name: str | None = typer.Option(
        None,
        "--workspace-name",
        envvar="SENTINEL_WORKSPACE_NAME",
    ),
) -> None:
    """Run entitlement-aware checks and write a static HTML dashboard."""
    workloads: list[Workload] | None = None
    if workload:
        try:
            workloads = [Workload(w.lower()) for w in workload]
        except ValueError as exc:
            console.print(f"[red]Invalid workload:[/red] {exc}")
            raise typer.Exit(code=2) from exc

    mode = _to_auth_mode(auth, live=live)
    workspace = _resolve_workspace_resource_id(
        workspace_resource_id, subscription_id, resource_group, workspace_name
    )
    try:
        auth_ctx = build_auth_context(
            mode=mode,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
    except AuthError as exc:
        console.print(f"[red]Auth configuration error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    for warning in auth_ctx.warnings:
        console.print(f"[yellow]Warning:[/yellow] {warning}")

    label = "live" if live else "dry-run"
    console.print(f"[cyan]Running {__product_name__} scan ({label})…[/cyan]")

    try:
        result = run_scan(
            auth_ctx,
            workloads=workloads,
            dry_run=not live,
            workspace_resource_id=workspace,
        )
    except (AuthError, GraphError) as exc:
        console.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    for warning in result.warnings:
        if warning not in auth_ctx.warnings:
            console.print(f"[yellow]Warning:[/yellow] {warning}")

    output_dir.mkdir(parents=True, exist_ok=True)
    html_path = write_html_report(result, output_dir / "security-license-lens-report.html")
    json_path = write_json_report(result, output_dir / "security-license-lens-report.json")
    md_path = write_markdown_report(result, output_dir / "security-license-lens-report.md")

    counts = result.counts_by_status
    org = result.tenant_display_name or result.tenant_id or "n/a"
    console.print(
        f"[green]Done.[/green] org={org} mode={result.scan_mode} "
        f"skus={len(result.subscribed_skus)} "
        f"capabilities={len(result.owned_capabilities)} "
        f"findings={len(result.findings)} status_counts={counts}"
    )
    console.print(f"  HTML  {html_path}")
    console.print(f"  JSON  {json_path}")
    console.print(f"  MD    {md_path}")

    _exit_for_scan(result.has_actionable_gaps)


@app.command("diff")
def diff_cmd(
    old_json: Path = typer.Argument(..., help="Baseline scan JSON report."),
    new_json: Path = typer.Argument(..., help="Newer scan JSON report."),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path (.md or .json). Defaults to <new>-diff.md.",
    ),
) -> None:
    """Compare two scan JSON artifacts by check_id."""
    if not old_json.is_file():
        console.print(f"[red]Baseline report not found:[/red] {old_json}")
        raise typer.Exit(code=2)
    if not new_json.is_file():
        console.print(f"[red]New report not found:[/red] {new_json}")
        raise typer.Exit(code=2)

    out = output or new_json.with_name(f"{new_json.stem}-diff.md")
    try:
        write_diff_report(old_json, new_json, out)
    except (OSError, ValueError) as exc:
        console.print(f"[red]Diff failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    console.print(f"  Diff  {out}")
    raise typer.Exit(code=0)


@app.command("batch")
def batch_cmd(
    config: Path = typer.Argument(..., help="Path to tenants.yaml."),
    output_dir: Path = typer.Option(
        Path("reports"),
        "--output-dir",
        "-o",
        help="Root directory for per-tenant reports and index.md.",
    ),
    live: bool = typer.Option(
        False,
        "--live/--dry-run",
        help="Run live scans (default: dry-run demo data per tenant).",
    ),
) -> None:
    """Run scans for every tenant listed in a tenants.yaml config."""
    if not config.is_file():
        console.print(f"[red]Config not found:[/red] {config}")
        raise typer.Exit(code=2)

    console.print(f"[cyan]Running batch scan from {config}…[/cyan]")
    try:
        rows = run_batch(config, output_dir=output_dir, dry_run=not live)
    except (LicenseLensError, OSError, ValueError) as exc:
        console.print(f"[red]Batch failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    table = Table(title="Batch results")
    table.add_column("Tenant")
    table.add_column("Tenant ID")
    table.add_column("Status")
    table.add_column("Gaps")
    table.add_column("Report")
    for row in rows:
        table.add_row(
            row["slug"],
            row.get("tenant_id") or "—",
            "ok" if row.get("status") == "ok" else "error",
            str(row.get("gaps") or "—"),
            row.get("report_dir") or row.get("error") or "—",
        )
    console.print(table)

    errors = [r for r in rows if r.get("status") != "ok"]
    raise typer.Exit(code=2 if errors else 0)


@app.command("discover-workspace")
def discover_workspace_cmd(
    auth: AuthModeOption | None = typer.Option(
        None,
        "--auth",
        help="Live auth mode: device | client_secret | azure_cli.",
    ),
    tenant_id: str | None = typer.Option(None, "--tenant-id", envvar="AZURE_TENANT_ID"),
    client_id: str | None = typer.Option(None, "--client-id", envvar="AZURE_CLIENT_ID"),
    client_secret: str | None = typer.Option(
        None,
        "--client-secret",
        envvar="AZURE_CLIENT_SECRET",
        help="Client secret (prefer env AZURE_CLIENT_SECRET).",
    ),
    subscription_id: str | None = typer.Option(
        None,
        "--subscription-id",
        envvar="AZURE_SUBSCRIPTION_ID",
        help="Restrict discovery to one subscription.",
    ),
    max_subscriptions: int = typer.Option(
        10,
        "--max-subscriptions",
        help="Cap on subscriptions scanned during discovery.",
    ),
) -> None:
    """Discover Sentinel-capable Log Analytics workspaces in a tenant."""
    mode = _to_auth_mode(auth, live=True)
    try:
        ctx = build_auth_context(
            mode=mode,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
    except AuthError as exc:
        console.print(f"[red]Auth configuration error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    for warning in ctx.warnings:
        console.print(f"[yellow]Warning:[/yellow] {warning}")

    console.print("[cyan]Discovering Sentinel workspaces…[/cyan]")
    try:
        found = discover_sentinel_workspaces(
            ctx,
            subscription_id=subscription_id,
            max_subscriptions=max_subscriptions,
        )
    except (AuthError, GraphError) as exc:
        console.print(f"[red]Discovery failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if not found:
        console.print("[yellow]No Sentinel-capable workspaces discovered.[/yellow]")
        raise typer.Exit(code=1)
    for rid in found:
        console.print(rid)
    raise typer.Exit(code=0)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
