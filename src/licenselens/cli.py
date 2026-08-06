"""Security License Lens command-line interface."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from licenselens import __cli_name__, __product_name__, __version__
from licenselens.auth import AuthMode, build_auth_context
from licenselens.engine.loader import load_checks
from licenselens.engine.runner import run_scan
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


@app.command("version")
def version_cmd() -> None:
    """Print the Security License Lens version."""
    console.print(f"{__product_name__} ({__cli_name__}) {__version__}")


@app.command("checks")
def checks_cmd(
    list_only: bool = typer.Option(
        True,
        "--list/--no-list",
        help="List registered checks.",
    ),
) -> None:
    """List registered checks from the checks/ tree."""
    del list_only  # reserved for future filters
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
    dry_run: bool = typer.Option(
        True,
        "--dry-run/--live",
        help="Dry-run uses demo entitlements (default). Live Graph is not ready yet.",
    ),
    tenant_id: str | None = typer.Option(
        None,
        "--tenant-id",
        help="Target tenant ID (live mode).",
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

    auth = build_auth_context(
        mode=AuthMode.DRY_RUN if dry_run else AuthMode.DEVICE_CODE,
        tenant_id=tenant_id,
    )

    if not dry_run:
        console.print(
            "[red]Live scan is not implemented in this scaffold. "
            "Use the default --dry-run.[/red]"
        )
        raise typer.Exit(code=2)

    console.print(f"[cyan]Running {__product_name__} scan (dry-run)…[/cyan]")
    result = run_scan(auth, workloads=workloads, dry_run=dry_run)

    output_dir.mkdir(parents=True, exist_ok=True)
    html_path = write_html_report(result, output_dir / "security-license-lens-report.html")
    json_path = write_json_report(result, output_dir / "security-license-lens-report.json")
    md_path = write_markdown_report(result, output_dir / "security-license-lens-report.md")

    counts = result.counts_by_status
    console.print(
        f"[green]Done.[/green] findings={len(result.findings)} "
        f"owned_capabilities={len(result.owned_capabilities)} "
        f"status_counts={counts}"
    )
    console.print(f"  HTML  {html_path}")
    console.print(f"  JSON  {json_path}")
    console.print(f"  MD    {md_path}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
