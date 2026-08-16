"""Orchestrate a scan: entitlements → eligible checks → findings."""

from __future__ import annotations

from datetime import UTC, datetime

from licenselens import __version__
from licenselens.auth import AuthContext, AuthMode
from licenselens.catalog.loader import capability_summaries_for, load_capabilities
from licenselens.engine.custom_rules import CustomRuleContext, evaluate_custom_rules
from licenselens.engine.loader import load_checks
from licenselens.engine.planner import ProgressCallback
from licenselens.engine.profiles import (
    ResolvedProfile,
    accepted_risk_annotations,
    apply_profile_to_findings,
)
from licenselens.engine.quality import scan_level_limitations
from licenselens.engine.rank import rank_moves, recommended_next_steps_from_moves
from licenselens.engine.registry import default_registry
from licenselens.engine.rollup import capability_rollup
from licenselens.engine.runner_collect import collect_scan_state
from licenselens.engine.runner_evaluate import evaluate_check
from licenselens.engine.runner_findings import STATUS_PRIORITY
from licenselens.graph import GraphClient
from licenselens.models import (
    DEFAULT_PACKS,
    CheckPack,
    ExposureClass,
    FindingStatus,
    ScanResult,
    Workload,
)

_evaluate_check = evaluate_check


def run_scan(
    auth: AuthContext,
    *,
    workloads: list[Workload] | None = None,
    dry_run: bool = True,
    workspace_resource_id: str | None = None,
    strict_proxy: bool = True,
    allow_email_proxy: bool = False,
    tenant_slug: str | None = None,
    discover_workspaces: bool = False,
    packs: list[CheckPack] | list[str] | None = None,
    profile: ResolvedProfile | None = None,
    scanned_at: datetime | None = None,
    progress: ProgressCallback | None = None,
) -> ScanResult:
    capabilities = load_capabilities()
    warnings = list(auth.warnings)
    scan_mode = "dry_run" if dry_run or auth.mode == AuthMode.DRY_RUN else "live"
    scan_time = scanned_at or datetime.now(UTC)
    registry = default_registry()

    state = collect_scan_state(
        auth=auth,
        scan_mode=scan_mode,
        capabilities=capabilities,
        warnings=warnings,
        workspace_resource_id=workspace_resource_id,
        allow_email_proxy=allow_email_proxy,
        discover_workspaces=discover_workspaces,
        profile=profile,
        workloads=workloads,
        registry=registry,
        tenant_id=auth.tenant_id,
        progress=progress,
    )
    evidence = state.evidence
    evidence["scanned_at"] = scan_time.isoformat()
    summaries = capability_summaries_for(capabilities, state.owned, state.skus)

    email_proxy = allow_email_proxy or (
        profile is not None and profile.profile.backend_preferences.allow_proxy
    )
    findings = [
        evaluate_check(
            check,
            state.owned_set,
            evidence,
            strict_proxy=strict_proxy,
            allow_email_proxy=email_proxy,
            registry=registry,
        )
        for check in state.checks
    ]
    findings.sort(
        key=lambda finding: (
            STATUS_PRIORITY.get(finding.status, 99),
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                finding.severity.value, 9
            ),
            finding.check_id,
        )
    )
    if profile is not None:
        findings = apply_profile_to_findings(findings, profile)
        findings.extend(
            evaluate_custom_rules(
                profile.profile,
                CustomRuleContext(
                    findings=findings,
                    tenant_domains=profile.profile.sensitive_domains,
                    sensitive_users=profile.profile.sensitive_users,
                    collection_summaries=state.collection_summaries,
                    profile_ids=profile.profile_ids,
                ),
            )
        )
        findings.sort(
            key=lambda finding: (
                STATUS_PRIORITY.get(finding.status, 99),
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                    finding.severity.value, 9
                ),
                finding.check_id,
            )
        )

    live_pending = [finding for finding in findings if finding.status == FindingStatus.SKIPPED]
    if scan_mode == "live" and live_pending:
        missing_eval = [
            finding.check_id
            for finding in live_pending
            if (finding.evidence or {}).get("email_proxy_enabled") is not False
        ]
        unreadable = [
            finding.check_id
            for finding in live_pending
            if (finding.evidence or {}).get("email_proxy_enabled") is False
        ]
        if missing_eval:
            warnings.append(
                "Some configuration checks are not implemented yet and were marked "
                f"pending: {', '.join(sorted(missing_eval))}."
            )
        if unreadable:
            warnings.append(
                "Email policy config cannot be read via Microsoft Graph "
                "(PowerShell / portal only). Pass --allow-email-proxy for a labeled "
                f"Secure Score degraded path. Affected checks: {', '.join(sorted(unreadable))}."
            )

    data_sources_used = sorted({source for finding in findings for source in finding.data_sources})
    limitations = scan_level_limitations(findings, strict_proxy=strict_proxy)

    pack_scope = packs if packs is not None else DEFAULT_PACKS
    if profile is not None and packs is None:
        pack_scope = profile.profile.packs
    pack_values = [pack.value if isinstance(pack, CheckPack) else str(pack) for pack in pack_scope]
    moves = rank_moves(findings, limit=3, packs=pack_scope)
    rollup, outcomes = capability_rollup(
        load_checks(),
        findings,
        state.owned,
        summaries,
        packs_scanned=pack_scope,
    )
    exposed_ids = [
        finding.check_id for finding in findings if finding.exposure_class == ExposureClass.EXPOSED
    ]

    return ScanResult(
        version=__version__,
        tenant_id=state.tenant_id,
        tenant_display_name=state.tenant_display_name,
        tenant_slug=tenant_slug,
        scan_mode=scan_mode,
        auth_mode=auth.mode.value,
        scanned_at=scan_time.isoformat(),
        owned_capabilities=state.owned,
        capability_summaries=summaries,
        subscribed_skus=state.skus,
        findings=findings,
        profile_ids=profile.profile_ids if profile is not None else [],
        accepted_risks=(accepted_risk_annotations(profile.profile) if profile is not None else []),
        recommended_next_steps=recommended_next_steps_from_moves(moves),
        warnings=warnings,
        limitations=limitations,
        data_sources_used=data_sources_used,
        workspace_resource_id=state.workspace_resource_id or evidence.get("workspace_resource_id"),
        strict_proxy=strict_proxy,
        packs_scanned=pack_values,
        moves=moves,
        capability_rollup=rollup,
        capability_outcomes=outcomes,
        has_exposed=bool(exposed_ids),
        exposed_check_ids=sorted(set(exposed_ids)),
        collection_summaries=state.collection_summaries,
    )


__all__ = ["GraphClient", "run_scan", "_evaluate_check"]
