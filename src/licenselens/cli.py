"""Security License Lens command-line interface."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Final

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from licenselens import __cli_name__, __product_name__, __version__
from licenselens.auth import (
    DEFAULT_PUBLIC_CLIENT_ID,
    REQUIRED_GRAPH_APP_PERMISSIONS,
    AuthMode,
    build_auth_context,
)
from licenselens.batch import run_batch
from licenselens.cli_profile_info import checks_listing_rows, profile_requirement_report
from licenselens.cli_scan_config import (
    ScanConfigError,
    resolve_scan_profile,
    write_report_archive,
)
from licenselens.collectors.contracts import EvidenceEnvelope
from licenselens.collectors.arm import build_workspace_resource_id
from licenselens.collectors.workspace_discover import discover_sentinel_workspaces
from licenselens.config_models import RedactionSettings
from licenselens.diff_report import write_diff_report
from licenselens.doctor import run_doctor
from licenselens.engine.loader import load_checks
from licenselens.engine.profiles import ResolvedProfile, load_builtin_profiles
from licenselens.engine.runner import run_scan
from licenselens.errors import AuthConfigError, AuthError, GraphError, LicenseLensError
from licenselens.models import CheckDefinition, CheckPack, ScanResult, Workload
from licenselens.report import write_html_report, write_json_report, write_markdown_report
from licenselens.schema_contracts import CollectionStatus

app = typer.Typer(
    name=__cli_name__,
    help=(
        f"{__product_name__}: entitlements, controls, and configuration gaps.\n\n"
        "Start here:  licenselens demo\n"
        "Then:        licenselens scan   (prompts when interactive)\n"
        "MSP path:    licenselens batch tenants.yaml"
    ),
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()


@app.callback(invoke_without_command=True)
def _version_callback(
    version: bool = typer.Option(
        False,
        "--version",
        help="Print the version and exit.",
        is_eager=True,
    ),
) -> None:
    """Handle top-level options shared by every command."""
    if version:
        console.print(f"{__cli_name__} {__version__}")
        raise typer.Exit(code=0)


#: Cool technical-blue identity accent — reserved for identity and
#: informational CLI framing. Never used for semantic status outcomes.
IDENTITY_ACCENT = "#88b4d8"


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


def _print_top_card(result) -> None:
    """Print the executive summary: what you own, what works, what to do first."""
    rollup = result.capability_rollup
    exposed_titles = ", ".join(
        finding.display_customer_title
        for finding in result.findings
        if finding.check_id in result.exposed_check_ids
    )
    lines = [
        f"Licensed capabilities detected: {len(result.owned_capabilities)}",
        f"Prioritized now ({', '.join(result.packs_scanned)}): {rollup.you_own}",
        f"Fully working (prioritized): {rollup.fully_working}  "
        f"({rollup.realized_percent}% realized)",
        f"Need attention (prioritized): {rollup.needs_attention + rollup.partly_set_up}",
    ]
    if result.moves:
        lines.append("")
        lines.append("Priority actions:")
        for move in result.moves:
            effort = f" [dim]({move.effort_label.lower()})[/dim]" if move.effort_label else ""
            lines.append(f"  • {move.title}{effort}")
    if result.has_exposed:
        lines.append(f"\n[red]EXPOSED ({result.exposed_count}):[/red] {exposed_titles}")
    console.print(Panel("\n".join(lines), title="Security posture", border_style=IDENTITY_ACCENT))


def _exit_for_scan(result_has_gaps: bool, *, errored: bool = False) -> None:
    if errored:
        raise typer.Exit(code=2)
    if result_has_gaps:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


def _resolve_profile_or_exit(
    *,
    profile: str | None,
    config: Path | None,
    rules: Path | None,
    backend: list[str] | None,
) -> ResolvedProfile | None:
    """Resolve assessment profile flags before auth; exit 2 on invalid config."""
    try:
        return resolve_scan_profile(
            profile_id=profile,
            config_path=config,
            rules_path=rules,
            backends=backend,
        )
    except ScanConfigError as exc:
        message = str(exc)
        if message.startswith("unknown profile:"):
            available = ", ".join(str(p.id) for p in load_builtin_profiles())
            message = (
                f"{message} Available assessment profile ids for --profile: "
                f"{available}. (doctor --profile is different: basic or full probe depth.)"
            )
        console.print(f"[red]Configuration error:[/red] {message}")
        raise typer.Exit(code=2) from exc


def _effective_redaction_settings(
    resolved_profile: ResolvedProfile | None,
    redact: bool | None,
) -> RedactionSettings:
    """Merge the --redact/--no-redact flag over the resolved profile's settings.

    The base is the resolved profile's ``redaction`` block; when no profile is
    in play the schema default (``enabled: True``) applies, so reports are
    redacted by default and ``--no-redact`` is the explicit opt-out.
    """
    settings = (
        resolved_profile.profile.redaction if resolved_profile is not None else RedactionSettings()
    )
    if redact is not None:
        settings = settings.model_copy(update={"enabled": redact})
    return settings


#: Canonical report artifact filenames. Any existing file means a prior run's
#: baseline lives in the output dir and must not be silently clobbered.
_REPORT_ARTIFACT_NAMES: Final = (
    "security-license-lens-report.html",
    "security-license-lens-report.json",
    "security-license-lens-report.md",
    "security-license-lens-report.zip",
)


def _divert_to_fresh_subdir(output_dir: Path) -> Path:
    """Return a fresh per-run subdirectory so a prior scan is preserved."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    candidate = output_dir / f"scan-{stamp}"
    counter = 1
    while candidate.exists():
        counter += 1
        candidate = output_dir / f"scan-{stamp}-{counter}"
    return candidate


def _write_scan_artifacts(
    result: ScanResult,
    output_dir: Path,
    *,
    report_archive: bool,
    redaction: RedactionSettings,
) -> tuple[Path, Path, Path, Path | None]:
    """Write HTML/JSON/Markdown reports and optional deterministic ZIP archive.

    When the output dir already holds report artifacts from a prior run, this
    run is written to a fresh timestamped subdirectory instead of clobbering
    the previous scan's files (which are the diff baseline).
    """
    existing = [
        output_dir / name
        for name in _REPORT_ARTIFACT_NAMES
        if (output_dir / name).is_file()
    ]
    if existing:
        prior_dir = output_dir
        output_dir = _divert_to_fresh_subdir(output_dir)
        console.print(
            f"[yellow]Prior report files found in {prior_dir} — preserving them "
            f"for diffing. Writing this run to {output_dir}[/yellow]"
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    html_path = write_html_report(
        result, output_dir / "security-license-lens-report.html", redaction=redaction
    )
    json_path = write_json_report(
        result, output_dir / "security-license-lens-report.json", redaction=redaction
    )
    md_path = write_markdown_report(
        result, output_dir / "security-license-lens-report.md", redaction=redaction
    )
    archive_path: Path | None = None
    if report_archive:
        try:
            archive_path = write_report_archive(
                output_dir=output_dir,
                result=result,
                redaction=redaction,
            )
        except ScanConfigError as exc:
            console.print(f"[red]Report archive failed:[/red] {exc}")
            raise typer.Exit(code=2) from exc
    return html_path, json_path, md_path, archive_path


@app.command("version")
def version_cmd() -> None:
    """Print the Security License Lens version."""
    console.print(f"{__product_name__} ({__cli_name__}) {__version__}")


#: One-line purpose per Microsoft Graph permission. Keyed by permission name;
#: the names themselves come from ``auth.REQUIRED_GRAPH_APP_PERMISSIONS`` (the
#: single source of truth — never retyped here).
_GRAPH_PERMISSION_PURPOSES: dict[str, str] = {
    "AccessReview.Read.All": "access reviews and their decisions",
    "Application.Read.All": "app registrations and service principals",
    "AuditLog.Read.All": "directory and sign-in audit logs",
    "DelegatedPermissionGrant.Read.All": "OAuth consent grants across the tenant",
    "DeviceManagementConfiguration.Read.All": "Intune device configuration policies",
    "DeviceManagementManagedDevices.Read.All": "managed device inventory",
    "Directory.Read.All": "directory objects (users, groups, roles)",
    "Domain.Read.All": "registered tenant domains",
    "Organization.Read.All": "organization-level settings",
    "Policy.Read.All": "conditional access and identity protection policies",
    "RoleManagement.Read.Directory": "role assignments and PIM settings",
    "SecurityAlert.Read.All": "Microsoft 365 security alerts",
    "SecurityEvents.Read.All": "secure score and security events",
    "SecurityIncident.Read.All": "Microsoft 365 security incidents",
    "User.Read.All": "user profiles and sign-in data",
}


@app.command("setup")
@app.command("init")
def setup_cmd() -> None:
    """Scaffold the Entra app registration for live scans (offline guide).

    Prints the tenant-id location, app-registration steps for device-code and
    app-only auth, the required read-only Graph permissions, the admin-consent
    URL, and the flags/env vars for the next step. No network calls, no
    prompts — safe for non-TTY use and idempotent.
    """
    lines: list[str] = []

    lines.append("1) Find your tenant (Directory) ID")
    lines.append(
        "   Find it in Entra ID → Overview → Tenant ID "
        "(a GUID like xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)."
    )

    lines.append("")
    lines.append("2) Register the app")
    lines.append("   Entra admin center → App registrations → New registration:")
    lines.append(
        "   • Device code (interactive use): enable public client flows "
        "('Allow public client flows' → Yes)."
    )
    lines.append(
        "   • App-only (automation / MSP runbooks): add a client secret under "
        "'Certificates & secrets' instead."
    )

    lines.append("")
    lines.append("3) Add the Graph API permissions (application, read-only)")
    for perm in REQUIRED_GRAPH_APP_PERMISSIONS:
        purpose = _GRAPH_PERMISSION_PURPOSES.get(perm)
        lines.append(f"   • {perm}{f' — {purpose}' if purpose else ''}")

    lines.append("")
    lines.append("4) Grant admin consent")
    lines.append(
        "   https://login.microsoftonline.com/{tenant-id}/adminconsent?client_id={client-id}"
    )
    lines.append(
        "   Replace {tenant-id} and {client-id}, then sign in as a Global "
        "Administrator (or an admin with consent rights)."
    )

    lines.append("")
    lines.append("5) Point LicenseLens at the registration")
    lines.append("   --tenant-id    / AZURE_TENANT_ID        directory (tenant) ID")
    lines.append("   --client-id    / AZURE_CLIENT_ID        app (client) ID")
    lines.append("   --client-secret / AZURE_CLIENT_SECRET   app-only secret (client_secret mode)")
    lines.append("   licenselens doctor --live --auth client_secret")

    lines.append("")
    lines.append(
        "Device-code shortcut: without --client-id, LicenseLens uses the "
        "Microsoft Graph PowerShell public client "
        f"({DEFAULT_PUBLIC_CLIENT_ID}); many delegated scopes are already "
        "pre-consented on that app, so only --tenant-id is needed for a quick "
        "try. Register your own app for production assessments."
    )
    lines.append(
        "Full walkthrough (including MDE/Sentinel options): docs/app-registration.md"
    )

    console.print(
        Panel(
            "\n".join(lines),
            title="Entra app registration setup",
            border_style=IDENTITY_ACCENT,
        )
    )
    raise typer.Exit(code=0)


def _checks_json_payload(checks: list[CheckDefinition]) -> list[dict[str, object]]:
    """Machine-readable check inventory with full (untruncated) ids."""
    payload: list[dict[str, object]] = []
    for check, (_id, workload, severity, profiles_csv, backend, mode, state) in zip(
        checks, checks_listing_rows(checks), strict=True
    ):
        payload.append(
            {
                "id": check.id,
                "title": check.title,
                "workload": workload,
                "capabilities": list(check.required_capabilities),
                "severity": severity,
                "mode": mode,
                "state": state,
                "backend": backend,
                "profiles": [
                    profile_id
                    for profile_id in profiles_csv.split(",")
                    if profile_id and profile_id != "—"
                ],
            }
        )
    return payload


@app.command("checks")
def checks_cmd(
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit a JSON array of checks with full ids (no table truncation).",
    ),
) -> None:
    """List registered checks with profile, backend, mode, and state."""
    checks = load_checks()
    if json_output:
        console.file.write(json.dumps(_checks_json_payload(checks), indent=2) + "\n")
        raise typer.Exit(code=0)
    if not checks:
        console.print("[yellow]No checks found.[/yellow]")
        raise typer.Exit(code=0)

    table = Table(title=f"{__product_name__} checks")
    table.add_column("ID")
    table.add_column("Workload")
    table.add_column("Severity")
    table.add_column("Profiles")
    table.add_column("Backend")
    table.add_column("Mode")
    table.add_column("State")
    for row in checks_listing_rows(checks):
        table.add_row(*row)
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
    assessment_profile: list[str] | None = typer.Option(
        None,
        "--assessment-profile",
        help=(
            "Assessment profile id (e.g. identity, full). Prints required "
            "capabilities, permissions, and modules. Repeatable. "
            "Validated before any token request."
        ),
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
    if assessment_profile:
        for profile_id in assessment_profile:
            try:
                req = profile_requirement_report(profile_id)
            except ScanConfigError as exc:
                console.print(f"[red]Configuration error:[/red] {exc}")
                raise typer.Exit(code=2) from exc
            console.print(
                Panel(
                    "\n".join(
                        [
                            f"Profile: {req.profile_id} ({req.profile_name})",
                            f"Checks ({len(req.check_ids)}): {', '.join(req.check_ids) or '—'}",
                            f"Capabilities: {', '.join(req.capabilities) or '—'}",
                            f"Permissions: {', '.join(req.permissions) or '—'}",
                            f"Backends: {', '.join(req.backends) or '—'}",
                            f"Modules: {', '.join(req.modules) or '—'}",
                        ]
                    ),
                    title="Assessment profile requirements",
                    border_style=IDENTITY_ACCENT,
                )
            )

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
    table.add_column("Status")
    table.add_column("Detail")
    for item in report.checks:
        if item.ok:
            status = "[green]✓[/green]"
        elif item.optional:
            status = "[yellow]⚠[/yellow]"
        else:
            status = "[red]✗[/red]"
        detail = item.detail
        if not item.ok and item.fix:
            detail = f"{detail}\n[dim]Fix: {item.fix}[/dim]"
        table.add_row(item.name, status, detail)
    console.print(table)

    if report.tenant_display_name or report.tenant_id:
        console.print(f"Tenant: {report.tenant_display_name or '—'} ({report.tenant_id or '—'})")
    if report.sku_count:
        console.print(f"Subscribed SKUs: {report.sku_count}")

    if not report.ready:
        console.print(
            "[red]Not ready — fix the ✗ items above, then re-run `licenselens doctor --live`.[/red]"
        )
        raise typer.Exit(code=2)
    if report.mode == AuthMode.DRY_RUN:
        console.print(
            "[dim]Dry-run — no live tenant calls were made; run "
            "`licenselens doctor --live` for a real preflight check.[/dim]"
        )
        raise typer.Exit(code=0)
    if not report.ok:
        console.print(
            "[yellow]Ready enough — identity scanning works. ⚠ items are optional "
            "probes (MDE/Sentinel) that are fine to leave unresolved.[/yellow]"
        )
    else:
        console.print("[green]Ready — all preflight checks passed.[/green]")
    raise typer.Exit(code=0)


_COLLECTION_STATUS_LABELS: dict[CollectionStatus, str] = {
    CollectionStatus.SUCCESS: "[green]ok[/green]",
    CollectionStatus.PARTIAL: "[yellow]partial[/yellow]",
    CollectionStatus.FAILED: "[red]failed[/red]",
    CollectionStatus.SKIPPED: "[dim]skipped[/dim]",
    CollectionStatus.UNSUPPORTED: "[dim]unsupported[/dim]",
}


def _emit_collection_progress(
    collector_id: str,
    index: int,
    total: int,
    envelope: EvidenceEnvelope,
) -> None:
    """Print one line per collected data source, with its outcome."""
    label = _COLLECTION_STATUS_LABELS[envelope.collection_status]
    items = envelope.metadata.items_collected
    item_text = f" ({items} items)" if items else ""
    console.print(f"  {index + 1:>2}/{total:<2} {str(envelope.key)} {label}{item_text}")


def _print_collection_summary(result: ScanResult) -> None:
    """Surface per-data-source collection outcomes after the scan."""
    summaries = result.collection_summaries
    if not summaries:
        return
    counts: dict[str, int] = {}
    for summary in summaries:
        counts[summary.status.value] = counts.get(summary.status.value, 0) + 1
    ok = counts.get("success", 0)
    flagged = [summary for summary in summaries if summary.status is not CollectionStatus.SUCCESS]
    if flagged:
        details = ", ".join(
            f"{status}={count}"
            for status, count in sorted(counts.items())
            if status != "success"
        )
        console.print(
            f"[dim]Collection summary: {len(summaries)} data sources — {ok} ok; {details}[/dim]"
        )
    else:
        console.print(f"[dim]Collection summary: {len(summaries)} data sources — all ok[/dim]")
    for summary in flagged:
        for warning in summary.warnings:
            console.print(f"[yellow]  {summary.collector}: {warning}[/yellow]")
        for error in summary.errors:
            console.print(f"[red]  {summary.collector}: {error}[/red]")


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
        help=(
            "Limit to workload(s): identity, email, collaboration, defender, sentinel, "
            "purview, endpoint."
        ),
    ),
    live: bool | None = typer.Option(
        None,
        "--live/--dry-run",
        help=(
            "Query a real tenant via Microsoft Graph. "
            "In an interactive terminal, omit this flag to be prompted "
            "(default without a TTY: dry-run demo data)."
        ),
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
    packs: list[str] | None = typer.Option(
        None,
        "--pack",
        help="Packs to include on the top card (default: identity, endpoint). "
        "Repeatable. Email is off by default — no Graph API for MDO policy config.",
    ),
    allow_email_proxy: bool = typer.Option(
        False,
        "--allow-email-proxy/--no-email-proxy",
        help="Opt into a labeled Secure Score proxy for the email pack "
        "(MDI/Purview also proxy when their packs are included). "
        "Email policy config is PowerShell-only — no Graph read API exists. "
        "Proxy findings never roll up to fully working.",
    ),
    open_browser: bool = typer.Option(
        False,
        "--open/--no-open",
        help="Open the generated HTML report in your browser.",
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        help="Assessment profile id (core, identity, full, …). Omit for legacy scope.",
    ),
    config: Path | None = typer.Option(
        None,
        "--config",
        help="Organization assessment profile YAML overlay (validated before auth).",
    ),
    rules: Path | None = typer.Option(
        None,
        "--rules",
        help="Custom rules YAML (list or {custom_rules: [...]}); validated before auth.",
    ),
    backend: list[str] | None = typer.Option(
        None,
        "--backend",
        help="Preferred collection backend(s): graph, arm, exchange_online, defender, "
        "secure_score, manual. Repeatable.",
    ),
    report_archive: bool = typer.Option(
        False,
        "--report-archive/--no-report-archive",
        help="Also write a deterministic offline report ZIP beside HTML/JSON.",
    ),
    redact: bool | None = typer.Option(
        None,
        "--redact/--no-redact",
        help=(
            "Redact tenant ids, user principal names, and tenant domains in "
            "HTML/JSON/Markdown reports and the report ZIP (default: the "
            "profile's redaction settings, which default to on). "
            "Use --no-redact to keep raw values."
        ),
    ),
) -> None:
    """Run entitlement-aware checks and write a static HTML dashboard.

    In an interactive terminal, missing options are prompted. Flags and env vars
    always win when already set.
    """
    from licenselens.cli_prompts import is_interactive, resolve_scan_inputs

    resolved_profile = _resolve_profile_or_exit(
        profile=profile, config=config, rules=rules, backend=backend
    )
    redaction = _effective_redaction_settings(resolved_profile, redact)

    workloads: list[Workload] | None = None
    if workload:
        try:
            workloads = [Workload(w.lower()) for w in workload]
        except ValueError as exc:
            console.print(f"[red]Invalid workload:[/red] {exc}")
            raise typer.Exit(code=2) from exc

    if packs:
        valid_packs = {p.value for p in CheckPack}
        for pack in packs:
            if pack.lower() not in valid_packs:
                console.print(
                    f"[red]Invalid pack:[/red] '{pack}'. "
                    f"Valid packs: {', '.join(sorted(valid_packs))}"
                )
                raise typer.Exit(code=2)

    workspace = _resolve_workspace_resource_id(
        workspace_resource_id, subscription_id, resource_group, workspace_name
    )
    wizard = resolve_scan_inputs(
        live=live,
        auth=auth.value if auth is not None else None,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        output_dir=output_dir,
        workspace_resource_id=workspace,
        open_browser=open_browser,
    )

    if live is None and not is_interactive():
        console.print(
            "[bold yellow]No terminal and no auth mode specified — running the "
            "offline demo (dry-run).[/bold yellow]"
        )
        console.print(
            "[bold yellow]Pass --live --tenant-id … for a real scan.[/bold yellow]"
        )

    try:
        auth_ctx = build_auth_context(
            mode=wizard.auth_mode,
            tenant_id=wizard.tenant_id,
            client_id=wizard.client_id,
            client_secret=wizard.client_secret,
        )
    except AuthError as exc:
        console.print(f"[red]Auth configuration error:[/red] {exc}")
        if wizard.live and not isinstance(exc, AuthConfigError):
            _print_device_code_rail()
        raise typer.Exit(code=2) from exc

    for warning in auth_ctx.warnings:
        console.print(f"[yellow]Warning:[/yellow] {warning}")

    if wizard.live and wizard.run_doctor:
        try:
            report = run_doctor(auth_ctx)
            org_label = report.tenant_display_name or report.tenant_id or "your organization"
            if not report.ready:
                console.print("[yellow]Preflight incomplete — some reads may be limited.[/yellow]")
            console.print(f"Connected to: [bold]{org_label}[/bold]")
            if not typer.confirm(f"Scan {org_label} now? (read-only)", default=True):
                console.print("Nothing was changed.")
                raise typer.Exit(code=0)
        except (LicenseLensError, ValueError) as exc:
            _print_device_code_rail()
            console.print(f"[red]Preflight failed:[/red] {exc}")
            raise typer.Exit(code=2) from exc

    label = "live" if wizard.live else "dry-run"
    console.print(
        f"[{IDENTITY_ACCENT}]Running {__product_name__} scan ({label})…[/{IDENTITY_ACCENT}]"
    )
    if resolved_profile is not None:
        console.print(
            f"[dim]Profile: {', '.join(resolved_profile.profile_ids)} "
            f"({len(resolved_profile.selected_check_ids)} checks)[/dim]"
        )

    try:
        result = run_scan(
            auth_ctx,
            workloads=workloads,
            dry_run=not wizard.live,
            workspace_resource_id=wizard.workspace_resource_id,
            packs=packs,
            allow_email_proxy=allow_email_proxy,
            profile=resolved_profile,
            progress=_emit_collection_progress,
        )
    except (AuthError, GraphError) as exc:
        if wizard.live:
            _print_device_code_rail()
        console.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    for warning in result.warnings:
        if warning not in auth_ctx.warnings:
            console.print(f"[yellow]Warning:[/yellow] {warning}")

    _print_collection_summary(result)

    html_path, json_path, md_path, archive_path = _write_scan_artifacts(
        result, wizard.output_dir, report_archive=report_archive, redaction=redaction
    )

    counts = result.counts_by_status
    org = result.tenant_display_name or result.tenant_id or "n/a"
    console.print(
        f"[green]Done.[/green] org={org} mode={result.scan_mode} "
        f"skus={len(result.subscribed_skus)} "
        f"capabilities={len(result.owned_capabilities)} "
        f"findings={len(result.findings)} status_counts={counts}"
    )
    _print_top_card(result)
    console.print(f"  HTML  {html_path}")
    console.print(f"  JSON  {json_path}")
    console.print(f"  MD    {md_path}")
    if archive_path is not None:
        console.print(f"  ZIP   {archive_path}")
    console.print(
        "[dim]To compare against a prior assessment: "
        "`licenselens diff <old.json> <new.json>`[/dim]"
    )

    if wizard.open_browser:
        import webbrowser

        webbrowser.open(str(html_path.resolve()))

    _exit_for_scan(result.has_actionable_gaps)


def _run_offline_demo(
    output_dir: Path,
    resolved_profile: ResolvedProfile | None,
    redaction: RedactionSettings,
    report_archive: bool,
) -> Path:
    """Run the offline demo scan, write artifacts, and print the summary."""
    auth = build_auth_context(mode=AuthMode.DRY_RUN)
    console.print(f"[{IDENTITY_ACCENT}]Running offline demo scan…[/{IDENTITY_ACCENT}]")
    result = run_scan(auth, dry_run=True, profile=resolved_profile)
    html_path, _json_path, _md_path, archive_path = _write_scan_artifacts(
        result, output_dir, report_archive=report_archive, redaction=redaction
    )
    _print_top_card(result)
    console.print(f"  HTML  {html_path}")
    if archive_path is not None:
        console.print(f"  ZIP   {archive_path}")
    console.print(
        "[green]Demo complete.[/green] This is a sample report from curated demo data — "
        "it is not a real tenant."
    )
    return html_path


@app.command("demo")
def demo_cmd(
    output_dir: Path = typer.Option(
        Path("reports"),
        "--output-dir",
        "-o",
        help="Directory for the demo HTML report.",
    ),
    open_browser: bool = typer.Option(
        False,
        "--open/--no-open",
        help="Open the generated HTML report in your browser.",
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        help="Assessment profile id (core, identity, full, …).",
    ),
    config: Path | None = typer.Option(
        None,
        "--config",
        help="Organization assessment profile YAML overlay.",
    ),
    rules: Path | None = typer.Option(
        None,
        "--rules",
        help="Custom rules YAML file.",
    ),
    backend: list[str] | None = typer.Option(
        None,
        "--backend",
        help="Preferred collection backend(s). Repeatable.",
    ),
    report_archive: bool = typer.Option(
        False,
        "--report-archive/--no-report-archive",
        help="Also write a deterministic offline report ZIP.",
    ),
    redact: bool | None = typer.Option(
        None,
        "--redact/--no-redact",
        help=(
            "Redact tenant ids, user principal names, and tenant domains in "
            "the reports (default: on). Use --no-redact to keep raw values."
        ),
    ),
) -> None:
    """Run the offline demo scan and print the HTML report path."""
    resolved_profile = _resolve_profile_or_exit(
        profile=profile, config=config, rules=rules, backend=backend
    )
    redaction = _effective_redaction_settings(resolved_profile, redact)
    html_path = _run_offline_demo(
        output_dir, resolved_profile, redaction, report_archive=report_archive
    )
    if open_browser:
        import webbrowser

        webbrowser.open(str(html_path.resolve()))
    raise typer.Exit(code=0)


@app.command("quickstart")
def quickstart_cmd(
    output_dir: Path = typer.Option(
        Path("reports"),
        "--output-dir",
        "-o",
        help="Directory for the scan reports.",
    ),
    tenant_id: str | None = typer.Option(None, "--tenant-id", envvar="AZURE_TENANT_ID"),
    client_id: str | None = typer.Option(None, "--client-id", envvar="AZURE_CLIENT_ID"),
    client_secret: str | None = typer.Option(
        None,
        "--client-secret",
        envvar="AZURE_CLIENT_SECRET",
        help="Optional app-only secret (prefer interactive device code).",
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        help="Assessment profile id (core, identity, full, …).",
    ),
    config: Path | None = typer.Option(
        None,
        "--config",
        help="Organization assessment profile YAML overlay.",
    ),
    rules: Path | None = typer.Option(
        None,
        "--rules",
        help="Custom rules YAML file.",
    ),
    backend: list[str] | None = typer.Option(
        None,
        "--backend",
        help="Preferred collection backend(s). Repeatable.",
    ),
    report_archive: bool = typer.Option(
        False,
        "--report-archive/--no-report-archive",
        help="Also write a deterministic offline report ZIP.",
    ),
    redact: bool | None = typer.Option(
        None,
        "--redact/--no-redact",
        help=(
            "Redact tenant ids, user principal names, and tenant domains in "
            "the reports (default: on). Use --no-redact to keep raw values."
        ),
    ),
) -> None:
    """Walk through a read-only scan against your own tenant (no code needed)."""
    from licenselens.cli_prompts import resolve_quickstart_inputs

    resolved_profile = _resolve_profile_or_exit(
        profile=profile, config=config, rules=rules, backend=backend
    )
    redaction = _effective_redaction_settings(resolved_profile, redact)
    console.print(
        Panel(
            "Security License Lens only reads. It never changes policies, users, "
            "or licenses.\nYou can run it yourself against your own Microsoft "
            "tenant — here is the 2-minute version.",
            title="Read-only check, yours to run",
            border_style=IDENTITY_ACCENT,
        )
    )

    wizard = resolve_quickstart_inputs(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )
    if wizard.fallback_demo:
        console.print(
            "[yellow]No tenant id provided, running the offline demo instead — "
            "pass --tenant-id or AZURE_TENANT_ID for a live walkthrough.[/yellow]"
        )
        _run_offline_demo(output_dir, resolved_profile, redaction, report_archive=report_archive)
        raise typer.Exit(code=0)

    if wizard.client_secret:
        mode = AuthMode.CLIENT_SECRET
    else:
        mode = AuthMode.DEVICE_CODE
    try:
        auth = build_auth_context(
            mode=mode,
            tenant_id=wizard.tenant_id,
            client_id=wizard.client_id,
            client_secret=wizard.client_secret,
        )
    except AuthConfigError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    except AuthError as exc:
        console.print(f"[red]{exc}[/red]")
        _print_device_code_rail()
        raise typer.Exit(code=2) from exc

    try:
        report = run_doctor(auth)
    except (LicenseLensError, ValueError) as exc:
        _print_device_code_rail()
        console.print(f"[red]Preflight failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    org = report.tenant_display_name or report.tenant_id or "your organization"
    if not report.ok:
        console.print("[yellow]Preflight incomplete — some reads may be limited.[/yellow]")
    console.print(f"Connected to: [bold]{org}[/bold]")
    if not typer.confirm(f"Scan {org} now? (read-only)", default=True):
        console.print("Nothing was changed. Run `licenselens doctor --live` anytime.")
        raise typer.Exit(code=0)

    try:
        result = run_scan(
            auth,
            dry_run=False,
            workspace_resource_id=None,
            profile=resolved_profile,
        )
    except (AuthError, GraphError) as exc:
        _print_device_code_rail()
        console.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    html_path, _json_path, _md_path, archive_path = _write_scan_artifacts(
        result, output_dir, report_archive=report_archive, redaction=redaction
    )
    _print_top_card(result)
    console.print(f"  HTML  {html_path}")
    if archive_path is not None:
        console.print(f"  ZIP   {archive_path}")
    console.print(
        "[green]Done.[/green] Open the HTML report and use the top-card list as your "
        "conversation starter with IT."
    )
    _exit_for_scan(result.has_actionable_gaps)


def _print_device_code_rail() -> None:
    """Plain-English guidance when interactive device-code sign-in is blocked."""
    console.print(
        Panel(
            "If your sign-in was blocked or you cannot complete the browser prompt, "
            "a conditional-access policy may be preventing interactive sign-in.\n"
            "Path for MSPs: use app-only access instead — create an app registration "
            "with the read-only Graph permissions in docs/app-registration.md, then:\n"
            "    export AZURE_TENANT_ID=... AZURE_CLIENT_ID=... AZURE_CLIENT_SECRET=...\n"
            "    licenselens scan --live --auth client_secret -o reports",
            title="Sign-in blocked? Use app-only instead",
            border_style="yellow",
        )
    )


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
    profile: str | None = typer.Option(
        None,
        "--profile",
        help="Default assessment profile for tenants that omit profile.",
    ),
    rules: Path | None = typer.Option(
        None,
        "--rules",
        help="Default custom rules YAML for the batch.",
    ),
    backend: list[str] | None = typer.Option(
        None,
        "--backend",
        help="Default preferred backend(s) for the batch. Repeatable.",
    ),
    report_archive: bool = typer.Option(
        False,
        "--report-archive/--no-report-archive",
        help="Write a deterministic offline report ZIP per tenant.",
    ),
) -> None:
    """Run scans for every tenant listed in a tenants.yaml config."""
    if not config.is_file():
        console.print(f"[red]Config not found:[/red] {config}")
        raise typer.Exit(code=2)

    _resolve_profile_or_exit(profile=profile, config=None, rules=rules, backend=backend)

    console.print(f"[{IDENTITY_ACCENT}]Running batch scan from {config}…[/{IDENTITY_ACCENT}]")
    try:
        rows = run_batch(
            config,
            output_dir=output_dir,
            dry_run=not live,
            profile_id=profile,
            rules_path=rules,
            backends=backend,
            report_archive=report_archive,
        )
    except (LicenseLensError, OSError, ValueError, ScanConfigError) as exc:
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

    console.print(f"[{IDENTITY_ACCENT}]Discovering Sentinel workspaces…[/{IDENTITY_ACCENT}]")
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
