"""Multi-tenant batch scan support."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from licenselens.auth import AuthMode, build_auth_context
from licenselens.cli_scan_config import resolve_scan_profile, write_report_archive
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


def load_tenants_config(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    defaults = raw.get("defaults") or {}
    if not isinstance(defaults, dict):
        defaults = {}
    tenants = raw.get("tenants") or []
    if not isinstance(tenants, list):
        raise ValueError("tenants.yaml must contain a top-level 'tenants' list")
    return defaults, [t for t in tenants if isinstance(t, dict)]


def _merged_entry(defaults: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    merged = dict(defaults)
    merged.update({k: v for k, v in entry.items() if v is not None})
    return merged


def _entry_backends(entry: dict[str, Any], cli_backends: list[str] | None) -> list[str] | None:
    raw = entry.get("backend") or entry.get("backends")
    if raw is None:
        return cli_backends
    if isinstance(raw, str):
        return [part.strip() for part in raw.split(",") if part.strip()]
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    return cli_backends


def _entry_path(entry: dict[str, Any], key: str, fallback: Path | None) -> Path | None:
    value = entry.get(key)
    if value is None or value == "":
        return fallback
    return Path(str(value))


def run_batch(
    config_path: Path,
    *,
    output_dir: Path,
    dry_run: bool = True,
    strict_proxy: bool = True,
    profile_id: str | None = None,
    rules_path: Path | None = None,
    backends: list[str] | None = None,
    report_archive: bool = False,
) -> list[dict[str, Any]]:
    """Run scans for each tenant entry; returns summary rows."""
    defaults, tenants = load_tenants_config(config_path)
    rows: list[dict[str, Any]] = []
    index_lines = [
        "# Security License Lens — batch index",
        "",
        f"Config: `{config_path}`",
        f"Mode: {'dry-run' if dry_run else 'live'}",
        "",
        "| Tenant | Status gaps | Exposed | Realized | Worst move | Report |",
        "|---|---|---:|---:|---|--:|",
    ]
    exposed_tenants: list[str] = []
    index_rows: list[tuple[tuple[object, ...], str]] = []

    for raw_entry in tenants:
        entry = _merged_entry(defaults, raw_entry)
        slug = str(entry.get("slug") or entry.get("tenant_id") or "tenant")
        tenant_id = entry.get("tenant_id") or entry.get("azure_tenant_id")
        default_mode = AuthMode.DRY_RUN if dry_run else AuthMode.CLIENT_SECRET
        mode = _parse_auth_mode(
            str(entry.get("auth_mode") or entry.get("auth") or default_mode.value),
            default=default_mode,
        )
        packs = entry.get("packs")
        if isinstance(packs, str):
            packs = [p.strip() for p in packs.split(",") if p.strip()]
        allow_email_proxy = bool(entry.get("allow_email_proxy", False))
        tenant_profile = entry.get("profile") or profile_id
        tenant_config = _entry_path(entry, "config", None)
        tenant_rules = _entry_path(entry, "rules", rules_path)
        tenant_backends = _entry_backends(entry, backends)
        tenant_archive = bool(entry.get("report_archive", report_archive))
        try:
            resolved_profile = resolve_scan_profile(
                profile_id=str(tenant_profile) if tenant_profile else None,
                config_path=tenant_config,
                rules_path=tenant_rules,
                backends=tenant_backends,
            )
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
                allow_email_proxy=allow_email_proxy,
                tenant_slug=slug,
                discover_workspaces=bool(entry.get("discover_workspaces")),
                packs=packs,
                profile=resolved_profile,
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
            if tenant_archive:
                write_report_archive(output_dir=out, result=result)
            gaps = result.counts_by_status.get("gap", 0) + result.counts_by_status.get("partial", 0)
            exposed = result.exposed_count
            if exposed:
                exposed_tenants.append(slug)
            realized = result.capability_rollup.realized_percent
            worst_move = result.moves[0].title if result.moves else "—"
            rows.append(
                {
                    "slug": slug,
                    "tenant_id": result.tenant_id,
                    "gaps": gaps,
                    "exposed": exposed,
                    "realized_percent": realized,
                    "worst_move": worst_move,
                    "status": "ok",
                    "report_dir": str(out),
                    "html": str(html),
                }
            )
            index_rows.append(
                (
                    (0 if exposed else 1, -exposed, realized, slug),
                    f"| {slug} | {gaps} | {exposed} | {realized}% | {worst_move} | `{out}` |",
                )
            )
        except Exception as exc:  # noqa: BLE001 — one bad tenant must not abort the batch
            rows.append(
                {
                    "slug": slug,
                    "tenant_id": tenant_id,
                    "gaps": None,
                    "exposed": None,
                    "realized_percent": None,
                    "worst_move": None,
                    "status": "error",
                    "report_dir": None,
                    "html": None,
                    "error": str(exc),
                }
            )
            index_rows.append(((2, 0, slug), f"| {slug} | error | — | — | — | {exc} |"))

    if exposed_tenants:
        index_lines.insert(
            4,
            "> **Exposed tenants:** "
            + ", ".join(f"`{s}`" for s in exposed_tenants)
            + " — fix these first.",
        )

    index_lines.extend(line for _, line in sorted(index_rows))
    index_path = output_dir / "index.md"
    output_dir.mkdir(parents=True, exist_ok=True)
    index_path.write_text("\n".join(index_lines) + "\n", encoding="utf-8")
    return rows


__all__ = ["load_tenants_config", "run_batch"]
