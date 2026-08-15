"""Collection-side helpers for scan orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from licenselens.auth import AuthContext
from licenselens.catalog.loader import resolve_owned_capabilities
from licenselens.collectors.runtime import collect_selected_evidence
from licenselens.collectors.skus import collect_subscribed_skus, collect_subscribed_skus_live
from licenselens.engine.collection_context import ScanCollectionContext
from licenselens.engine.loader import load_checks
from licenselens.engine.profiles import ResolvedProfile
from licenselens.engine.registry import AssessmentRegistry
from licenselens.errors import GraphError
from licenselens.graph import GraphClient, fetch_organization_context
from licenselens.models import CheckDefinition, SubscribedSku, Workload
from licenselens.schema_contracts import CollectionSummary


@dataclass(slots=True)
class CollectedScanState:
    """Evidence and entitlement state produced before evaluation."""

    tenant_id: str | None
    tenant_display_name: str | None
    workspace_resource_id: str | None
    skus: list[SubscribedSku]
    owned: list[str]
    owned_set: set[str]
    checks: list[CheckDefinition]
    evidence: dict[str, Any]
    collection_summaries: list[CollectionSummary]
    warnings: list[str]


def profile_collection_extras(profile: ResolvedProfile | None) -> dict[str, Any]:
    if profile is None:
        return {
            "break_glass_principal_ids": [],
            "approved_guest_domains": [],
        }
    bg_ids: list[str] = []
    approved_domains: list[str] = list(profile.profile.sensitive_domains)
    for exclusion in profile.profile.exclusions:
        if str(getattr(exclusion, "kind", "general")).lower() == "break_glass":
            bg_ids.extend(str(pid) for pid in exclusion.principal_ids if pid)
    return {
        "break_glass_principal_ids": sorted(set(bg_ids)),
        "approved_guest_domains": sorted(set(approved_domains)),
        "approved_partner_domains": sorted(set(profile.profile.sensitive_domains)),
        "sensitive_users": sorted(set(profile.profile.sensitive_users)),
        "sensitive_domains": sorted(set(profile.profile.sensitive_domains)),
        "allowed_forwarding_domains": sorted(set(profile.profile.allowed_forwarding_domains)),
        "dmarc_agency_contact": profile.profile.dmarc_agency_contact.strip(),
        "dmarc_federal_contact": profile.profile.dmarc_federal_contact.strip(),
    }


def select_checks(
    *,
    profile: ResolvedProfile | None,
    workloads: list[Workload] | None,
) -> list[CheckDefinition]:
    checks = [c for c in load_checks() if c.enabled]
    if profile is not None:
        selected_check_ids = set(profile.selected_check_ids)
        checks = [c for c in checks if c.id in selected_check_ids]
    if workloads:
        wanted = set(workloads)
        checks = [c for c in checks if c.workload in wanted]
    return checks


def maybe_discover_workspace(
    *,
    auth: AuthContext,
    scan_mode: str,
    discover_workspaces: bool,
    workspace_resource_id: str | None,
    owned_set: set[str],
    warnings: list[str],
) -> str | None:
    if (
        scan_mode != "live"
        or not discover_workspaces
        or workspace_resource_id
        or "microsoft_sentinel" not in owned_set
    ):
        return workspace_resource_id
    try:
        from licenselens.collectors.workspace_discover import discover_sentinel_workspaces

        discovered = discover_sentinel_workspaces(auth)
        if len(discovered) == 1:
            workspace_resource_id = discovered[0]
            warnings.append(f"Auto-discovered Sentinel workspace: {workspace_resource_id}")
            return workspace_resource_id
        if len(discovered) > 1:
            warnings.append(
                f"Found {len(discovered)} possible Sentinel workspaces; "
                "pass --workspace-resource-id explicitly (refusing to guess)."
            )
        else:
            warnings.append("Workspace auto-discover found no Sentinel workspaces.")
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Workspace auto-discover failed: {exc}")
    return workspace_resource_id


def _run_collection(
    *,
    scan_mode: str,
    auth: AuthContext,
    client: GraphClient | None,
    skus: list[SubscribedSku],
    capabilities: list[Any],
    warnings: list[str],
    workspace_resource_id: str | None,
    allow_email_proxy: bool,
    discover_workspaces: bool,
    profile: ResolvedProfile | None,
    workloads: list[Workload] | None,
    registry: AssessmentRegistry,
    tenant_id: str | None,
    tenant_display_name: str | None,
) -> CollectedScanState:
    owned = resolve_owned_capabilities(capabilities, skus)
    owned_set = set(owned)
    checks = select_checks(profile=profile, workloads=workloads)
    workspace_resource_id = maybe_discover_workspace(
        auth=auth,
        scan_mode=scan_mode,
        discover_workspaces=discover_workspaces,
        workspace_resource_id=workspace_resource_id,
        owned_set=owned_set,
        warnings=warnings,
    )
    email_proxy = allow_email_proxy or (
        profile is not None and profile.profile.backend_preferences.allow_proxy
    )
    ctx = ScanCollectionContext(
        scan_mode=scan_mode,
        auth=auth,
        client=client,
        skus=skus,
        warnings=warnings,
        workspace_resource_id=workspace_resource_id,
        allow_email_proxy=email_proxy,
        discover_workspaces=discover_workspaces,
        extras=profile_collection_extras(profile),
    )
    evidence, collection_summaries, _result = collect_selected_evidence(
        ctx,
        registry,
        check_ids=[c.id for c in checks],
        profile_ids=tuple(profile.profile_ids) if profile is not None else (),
    )
    return CollectedScanState(
        tenant_id=tenant_id,
        tenant_display_name=tenant_display_name,
        workspace_resource_id=workspace_resource_id,
        skus=skus,
        owned=owned,
        owned_set=owned_set,
        checks=checks,
        evidence=evidence,
        collection_summaries=collection_summaries,
        warnings=warnings,
    )


def collect_scan_state(
    *,
    auth: AuthContext,
    scan_mode: str,
    capabilities: list[Any],
    warnings: list[str],
    workspace_resource_id: str | None,
    allow_email_proxy: bool,
    discover_workspaces: bool,
    profile: ResolvedProfile | None,
    workloads: list[Workload] | None,
    registry: AssessmentRegistry,
    tenant_id: str | None,
) -> CollectedScanState:
    """Resolve entitlements and collect evidence for the selected checks."""
    tenant_display_name: str | None = None
    if scan_mode == "dry_run":
        skus = collect_subscribed_skus(auth, dry_run=True)
        return _run_collection(
            scan_mode=scan_mode,
            auth=auth,
            client=None,
            skus=skus,
            capabilities=capabilities,
            warnings=warnings,
            workspace_resource_id=workspace_resource_id,
            allow_email_proxy=allow_email_proxy,
            discover_workspaces=discover_workspaces,
            profile=profile,
            workloads=workloads,
            registry=registry,
            tenant_id=tenant_id or "00000000-0000-0000-0000-000000000000",
            tenant_display_name="Contoso Demo (dry-run)",
        )

    import importlib

    graph_client = importlib.import_module("licenselens.engine.runner").GraphClient
    with graph_client(auth) as client:
        try:
            org_id, org_name = fetch_organization_context(client)
            tenant_id = org_id or tenant_id
            tenant_display_name = org_name
        except GraphError as exc:
            warnings.append(f"Could not read organization profile: {exc}")
        try:
            skus = collect_subscribed_skus_live(client)
        except GraphError:
            raise
        return _run_collection(
            scan_mode=scan_mode,
            auth=auth,
            client=client,
            skus=skus,
            capabilities=capabilities,
            warnings=warnings,
            workspace_resource_id=workspace_resource_id,
            allow_email_proxy=allow_email_proxy,
            discover_workspaces=discover_workspaces,
            profile=profile,
            workloads=workloads,
            registry=registry,
            tenant_id=tenant_id,
            tenant_display_name=tenant_display_name,
        )
