"""Multi-tenant batch scan support."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from licenselens.auth import AuthMode, build_auth_context
from licenselens.engine.runner import run_scan
from licenselens.output import build_report_dir
from licenselens.report import write_html_report, write_json_report, write_markdown_report

_AUTH_MODE_ALIASES: dict[str, AuthMode] = {
    "dry_run": AuthMode.DRY_RUN,
    "dry-run": AuthMode.DRY_RUN,
    "device": AuthMode.DEVICE_CODE,
    "device_code": AuthMode.DEVICE_CODE,
    "device-code": AuthMode.DEVICE_CODE,
    "client_secret": AuthMode.CLIENT_SECRET,
    "client-secret": AuthMode.CLIENT_SECRET,
    "clientsecret": AuthMode.CLIENT_SECRET,
    "azure_cli": AuthMode.AZURE_CLI,
    "azure-cli": AuthMode.AZURE_CLI,
    "cli": AuthMode.AZURE_CLI,
}


def _parse_auth_mode(value: str, *, default: AuthMode) -> AuthMode:
    key = value.strip().lower()
    return _AUTH_MODE_ALIASES.get(key, default)


def load_tenants_config(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    tenants = raw.get("tenants") or []
    if not isinstance(tenants, list):
        raise ValueError("tenants.yaml must contain a top-level 'tenants' list")
    return [t for t in tenants if isinstance(t, dict)]


def run_batch(
    config_path: Path,
    *,
    output_dir: Path,
    dry_run: bool = True,
    strict_proxy: bool = True,
) -> list[dict[str, Any]]:
    """Run scans for each tenant entry; returns summary rows."""
    tenants = load_tenants_config(config_path)
    rows: list[dict[str, Any]] = []
    index_lines = [
        "# Security License Lens — batch index",
        "",
        f"Config: `{config_path}`",
        f"Mode: {'dry-run' if dry_run else 'live'}",
        "",
        "| Tenant | Status gaps | Report |",
        "|---|---:|---|",
    ]

    for entry in tenants:
        slug = str(entry.get("slug") or entry.get("tenant_id") or "tenant")
        tenant_id = entry.get("tenant_id") or entry.get("azure_tenant_id")
        default_mode = AuthMode.DRY_RUN if dry_run else AuthMode.CLIENT_SECRET
        mode = _parse_auth_mode(
            str(entry.get("auth_mode") or default_mode.value),
            default=default_mode,
        )
        try:
            auth = build_auth_context(
                mode=mode,
                tenant_id=tenant_id,
                client_id=entry.get("client_id"),
                client_secret=entry.get("client_secret"),
            )
            result = run_scan(
                auth,
                dry_run=dry_run or mode == AuthMode.DRY_RUN,
                workspace_resource_id=entry.get("workspace_resource_id"),
                strict_proxy=strict_proxy,
                tenant_slug=slug,
                discover_workspaces=bool(entry.get("discover_workspaces")),
            )
            out = build_report_dir(
                output_dir,
                tenant_slug=slug,
                tenant_id=result.tenant_id,
                tenant_display_name=result.tenant_display_name,
            )
            html = write_html_report(result, out / "security-license-lens-report.html")
            write_json_report(result, out / "security-license-lens-report.json")
            write_markdown_report(result, out / "security-license-lens-report.md")
            gaps = result.counts_by_status.get("gap", 0) + result.counts_by_status.get(
                "partial", 0
            )
            rows.append(
                {
                    "slug": slug,
                    "tenant_id": result.tenant_id,
                    "gaps": gaps,
                    "status": "ok",
                    "report_dir": str(out),
                    "html": str(html),
                }
            )
            index_lines.append(f"| {slug} | {gaps} | `{out}` |")
        except Exception as exc:  # noqa: BLE001 — one bad tenant must not abort the batch
            rows.append(
                {
                    "slug": slug,
                    "tenant_id": tenant_id,
                    "gaps": None,
                    "status": "error",
                    "report_dir": None,
                    "html": None,
                    "error": str(exc),
                }
            )
            index_lines.append(f"| {slug} | error | {exc} |")

    index_path = output_dir / "index.md"
    output_dir.mkdir(parents=True, exist_ok=True)
    index_path.write_text("\n".join(index_lines) + "\n", encoding="utf-8")
    return rows
