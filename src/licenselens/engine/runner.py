"""Orchestrate a scan: entitlements → eligible checks → findings."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from licenselens import __version__
from licenselens.auth import AuthContext, AuthMode
from licenselens.catalog.loader import (
    capability_summaries_for,
    load_capabilities,
    resolve_owned_capabilities,
)
from licenselens.collectors.runtime import collect_selected_evidence
from licenselens.collectors.skus import collect_subscribed_skus, collect_subscribed_skus_live
from licenselens.engine.collection_context import ScanCollectionContext
from licenselens.engine.custom_rules import CustomRuleContext, evaluate_custom_rules
from licenselens.engine.evaluate import Evaluation
from licenselens.engine.loader import load_checks
from licenselens.engine.profiles import (
    ResolvedProfile,
    accepted_risk_annotations,
    apply_profile_to_findings,
)
from licenselens.engine.quality import apply_quality_policy, scan_level_limitations
from licenselens.engine.rank import (
    rank_moves,
    recommended_next_steps_from_moves,
)
from licenselens.engine.registry import AssessmentRegistry, default_registry
from licenselens.engine.rollup import capability_rollup
from licenselens.errors import GraphError
from licenselens.graph import GraphClient, fetch_organization_context
from licenselens.models import (
    DEFAULT_PACKS,
    STATUS_PLAIN_LABELS,
    CheckDefinition,
    CheckPack,
    Confidence,
    ExposureClass,
    Finding,
    FindingStatus,
    ScanResult,
    Workload,
)
from licenselens.schema_contracts import CollectionSummary, EvaluationMode

_STATUS_PRIORITY = {
    FindingStatus.GAP: 0,
    FindingStatus.PARTIAL: 1,
    FindingStatus.SKIPPED: 2,
    FindingStatus.ERROR: 3,
    FindingStatus.OK: 4,
    FindingStatus.NOT_LICENSED: 5,
}


def _eligible(check: CheckDefinition, owned: set[str]) -> bool:
    if not check.required_capabilities:
        return True
    return any(cap in owned for cap in check.required_capabilities)


def _customer_fields(check: CheckDefinition) -> dict[str, str]:
    return {
        "customer_title": check.customer_title or check.title,
        "customer_summary": check.customer_summary or check.description,
        "customer_next_step": check.customer_next_step or check.remediation,
    }


def _finding_evaluation_mode(
    check: CheckDefinition, evidence: dict[str, Any] | None
) -> EvaluationMode:
    try:
        mode = default_registry().evaluator_for(check.id).evaluation_mode
    except KeyError:
        mode = EvaluationMode.DIRECT
    if mode == EvaluationMode.PROXY and (evidence or {}).get("proxy") is False:
        return EvaluationMode.DIRECT
    return mode


def _base_finding(
    check: CheckDefinition,
    *,
    status: FindingStatus,
    summary: str,
    owned: set[str],
    evidence: dict[str, Any] | None = None,
    customer_summary: str | None = None,
    customer_next_step: str | None = None,
    confidence: Confidence = Confidence.MEDIUM,
    data_sources: list[str] | None = None,
    limitations: list[str] | None = None,
    strict_proxy: bool = True,
) -> Finding:
    customer = _customer_fields(check)
    finding = Finding(
        check_id=check.id,
        title=check.title,
        workload=check.workload,
        status=status,
        severity=check.severity,
        value_impact=check.value_impact,
        impact=check.impact,
        effort=check.effort,
        blast_radius=check.blast_radius,
        pack=check.pack,
        exposure_class=check.exposure_class,
        deep_link=check.deep_link,
        summary=summary,
        customer_title=customer["customer_title"],
        customer_summary=customer_summary or customer["customer_summary"],
        customer_next_step=customer_next_step or customer["customer_next_step"],
        status_label=STATUS_PLAIN_LABELS[status.value],
        evidence=evidence or {},
        entitlements_used=[c for c in check.required_capabilities if c in owned],
        remediation=check.remediation,
        references=check.references,
        confidence=confidence,
        data_sources=list(data_sources or []),
        limitations=list(limitations or []),
        evaluation_mode=_finding_evaluation_mode(check, evidence),
    )
    finding = apply_quality_policy(finding, strict_proxy=strict_proxy)
    finding.status_label = STATUS_PLAIN_LABELS.get(finding.status.value, finding.status.value)
    return finding


def _not_licensed_finding(
    check: CheckDefinition, owned: set[str], *, strict_proxy: bool = True
) -> Finding:
    return _base_finding(
        check,
        status=FindingStatus.NOT_LICENSED,
        summary=("Required capability not detected in tenant entitlements; check skipped."),
        owned=owned,
        customer_summary=(
            "This protection does not appear to be included in the licenses "
            "we detected, so there is nothing to configure for it yet."
        ),
        customer_next_step=(
            "If you expected this capability, confirm the correct Microsoft "
            "plan is assigned, or talk to your licensing partner."
        ),
        evidence={},
        confidence=Confidence.HIGH,
        data_sources=["graph.subscribedSkus"],
        strict_proxy=strict_proxy,
    )


def _skipped_finding(
    check: CheckDefinition, owned: set[str], *, strict_proxy: bool = True
) -> Finding:
    source = check.source_path
    if source:
        source = source.replace("\\", "/").split("/checks/")[-1]
        if not source.startswith("checks/"):
            source = f"checks/{source}" if "checks/" not in source else source
    return _base_finding(
        check,
        status=FindingStatus.SKIPPED,
        summary=("Entitlements resolved, but this control check is not implemented yet."),
        owned=owned,
        evidence={"collector": check.collector, "source": source},
        confidence=Confidence.LOW,
        strict_proxy=strict_proxy,
    )


def _error_finding(
    check: CheckDefinition,
    owned: set[str],
    message: str,
    *,
    strict_proxy: bool = True,
) -> Finding:
    return _base_finding(
        check,
        status=FindingStatus.ERROR,
        summary=f"Could not evaluate check: {message}",
        owned=owned,
        customer_summary=(
            "We could not verify this protection automatically. This is often a "
            "permissions issue — see the technical summary and app registration guide."
        ),
        customer_next_step=(
            "Ask IT to confirm required permissions with admin consent "
            "(docs/permissions.md), then re-run doctor and scan."
        ),
        evidence={"error": message},
        confidence=Confidence.LOW,
        strict_proxy=strict_proxy,
    )


def _from_evaluation(
    check: CheckDefinition,
    owned: set[str],
    evaluation: Evaluation,
    *,
    strict_proxy: bool = True,
) -> Finding:
    finding = _base_finding(
        check,
        status=evaluation.status,
        summary=evaluation.summary,
        owned=owned,
        evidence=evaluation.evidence,
        customer_summary=evaluation.customer_summary,
        confidence=evaluation.confidence,
        data_sources=evaluation.data_sources,
        limitations=evaluation.limitations,
        strict_proxy=strict_proxy,
    )
    if evaluation.exposure_class != ExposureClass.NONE:
        finding.exposure_class = evaluation.exposure_class
    return finding


def _recommended_next_steps(findings: list[Finding], limit: int = 5) -> list[str]:
    actionable = [
        f
        for f in findings
        if f.status in {FindingStatus.GAP, FindingStatus.PARTIAL, FindingStatus.SKIPPED}
        and f.customer_next_step
    ]
    actionable.sort(
        key=lambda f: (
            _STATUS_PRIORITY.get(f.status, 99),
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity.value, 9),
        )
    )
    steps: list[str] = []
    seen: set[str] = set()
    for finding in actionable:
        step = finding.customer_next_step.strip()
        if not step or step in seen:
            continue
        seen.add(step)
        steps.append(step)
        if len(steps) >= limit:
            break
    return steps


_EMAIL_UNREADABLE_SUMMARY = (
    "Email protection policy config is not readable via Microsoft Graph "
    "(Safe Links / Safe Attachments / preset policies require Exchange Online "
    "PowerShell). Enable --allow-email-proxy for a labeled Secure Score "
    "degraded path, or verify in the Defender portal."
)

_EMAIL_UNREADABLE_CUSTOMER = (
    "We cannot automatically confirm whether extra email protections "
    "(Safe Links and Safe Attachments) cover everyone. Ask IT to check "
    "Preset security policies in the Microsoft Defender portal, or run "
    "Exchange Online PowerShell (Get-ATPProtectionPolicyRule)."
)

_EMAIL_UNREADABLE_NEXT = (
    "Open Preset security policies in the Defender portal and turn on "
    "Standard protection for all users, or confirm with Exchange Online PowerShell."
)


def _evaluate_check(
    check: CheckDefinition,
    owned: set[str],
    evidence: dict[str, Any],
    *,
    strict_proxy: bool = True,
    allow_email_proxy: bool = False,
    registry: AssessmentRegistry | None = None,
) -> Finding:
    if not _eligible(check, owned):
        return _not_licensed_finding(check, owned, strict_proxy=strict_proxy)

    assessment = registry if registry is not None else default_registry()
    try:
        entry = assessment.evaluator_for(check.id)
    except KeyError:
        return _skipped_finding(check, owned, strict_proxy=strict_proxy)
    evaluator = entry.evaluate
    if evaluator is None:
        return _skipped_finding(check, owned, strict_proxy=strict_proxy)

    # MDO: prefer direct Exchange PowerShell; Secure Score proxy is opt-in fallback only.
    if check.id == "mdo-p2-policies-default":
        if evidence.get("exchange_threat_usable"):
            pass  # evaluate via direct EXO evidence below
        elif not allow_email_proxy:
            return _base_finding(
                check,
                status=FindingStatus.SKIPPED,
                summary=_EMAIL_UNREADABLE_SUMMARY,
                owned=owned,
                customer_summary=_EMAIL_UNREADABLE_CUSTOMER,
                customer_next_step=_EMAIL_UNREADABLE_NEXT,
                evidence={
                    "source": "none",
                    "proxy": False,
                    "email_proxy_enabled": False,
                    "exchange_direct": False,
                    "note": (
                        "No Graph API reads MDO email policy config. "
                        "Direct path is Exchange Online PowerShell; "
                        "--allow-email-proxy enables labeled Secure Score fallback."
                    ),
                },
                confidence=Confidence.LOW,
                data_sources=[],
                limitations=[
                    "Email policy config is PowerShell-only unless direct EXO adapters succeed.",
                ],
                strict_proxy=strict_proxy,
            )

    required_keys = list(entry.input_models)
    _optional_missing = {
        "break_glass_principal_ids",
        "approved_guest_domains",
        "role_eligibilities",
    }
    _error_aliases = {
        "ca_policies": "ca_policies_error",
        "security_defaults_policy": "security_defaults_policy_error",
        "access_review_definitions": "access_review_definitions_error",
        "role_assignments": "role_assignments_error",
        "recent_signin_user_ids": "recent_signin_error",
        "principal_directory": "principal_directory_error",
        "secure_score_controls": "secure_score_controls_error",
        "mde_summary": "mde_summary_error",
        "sentinel_rules": "sentinel_rules_error",
        "sentinel_ueba": "sentinel_ueba_error",
        "sentinel_data_connectors": "sentinel_data_connectors_error",
        "sentinel_automation_rules": "sentinel_automation_rules_error",
        "sentinel_workspace": "sentinel_workspace_error",
        "defender_for_cloud_pricings": "defender_for_cloud_pricings_error",
        "purview_dlp": "purview_dlp_error",
        "auth_methods_bundle": "auth_methods_bundle_error",
        "applications_bundle": "applications_bundle_error",
        "authorization_policy": "authorization_policy_error",
        "admin_consent_request_policy": "authorization_policy_error",
        "guests_bundle": "guests_bundle_error",
        "pim_policies_bundle": "pim_policies_bundle_error",
        "domains": "domains_error",
        "exchange_bundle": "exchange_collect_error",
        "dns_records": "dns_records_error",
        "collaboration_bundle": "collaboration_collect_error",
        "power_data_bundle": "power_data_collect_error",
        "intune_bundle": "intune_bundle_error",
        "mde_health": "mde_health_error",
        "security_alerts_bundle": "security_alerts_bundle_error",
    }
    for key in required_keys:
        err_key = _error_aliases.get(key, f"{key}_error")
        if key == "secure_score_controls" and evidence.get("secure_score_controls_error"):
            if check.id == "mdo-p2-policies-default" and evidence.get("exchange_threat_usable"):
                continue
            return _error_finding(
                check,
                owned,
                str(evidence["secure_score_controls_error"]),
                strict_proxy=strict_proxy,
            )
        if key == "sentinel_ueba" and evidence.get("sentinel_ueba_error"):
            if "sentinel_ueba" not in evidence:
                return _error_finding(
                    check,
                    owned,
                    str(evidence["sentinel_ueba_error"]),
                    strict_proxy=strict_proxy,
                )
            continue
        if evidence.get(err_key) and key not in _optional_missing:
            return _error_finding(check, owned, str(evidence[err_key]), strict_proxy=strict_proxy)
        if key not in evidence and err_key not in evidence:
            if key in _optional_missing:
                continue
            if key in {
                "sentinel_rules",
                "sentinel_ueba",
                "sentinel_data_connectors",
                "sentinel_automation_rules",
                "sentinel_workspace",
            } and evidence.get("sentinel_workspace_missing"):
                continue
            return _error_finding(
                check,
                owned,
                f"Required evidence '{key}' was not collected.",
                strict_proxy=strict_proxy,
            )

    try:
        result = evaluator(check, evidence)
    except Exception as exc:  # noqa: BLE001
        return _error_finding(check, owned, str(exc), strict_proxy=strict_proxy)
    return _from_evaluation(check, owned, result, strict_proxy=strict_proxy)


def _profile_collection_extras(profile: ResolvedProfile | None) -> dict[str, Any]:
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


def _select_checks(
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


def _maybe_discover_workspace(
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
) -> ScanResult:
    capabilities = load_capabilities()
    warnings = list(auth.warnings)
    tenant_id = auth.tenant_id
    tenant_display_name: str | None = None
    scan_mode = "dry_run" if dry_run or auth.mode == AuthMode.DRY_RUN else "live"
    scan_time = scanned_at or datetime.now(UTC)
    registry = default_registry()
    collection_summaries: list[CollectionSummary] = []

    if scan_mode == "dry_run":
        skus = collect_subscribed_skus(auth, dry_run=True)
        tenant_id = tenant_id or "00000000-0000-0000-0000-000000000000"
        tenant_display_name = tenant_display_name or "Contoso Demo (dry-run)"
        client: GraphClient | None = None
        owned = resolve_owned_capabilities(capabilities, skus)
        owned_set = set(owned)
        checks = _select_checks(profile=profile, workloads=workloads)
        workspace_resource_id = _maybe_discover_workspace(
            auth=auth,
            scan_mode=scan_mode,
            discover_workspaces=discover_workspaces,
            workspace_resource_id=workspace_resource_id,
            owned_set=owned_set,
            warnings=warnings,
        )
        ctx = ScanCollectionContext(
            scan_mode=scan_mode,
            auth=auth,
            client=client,
            skus=skus,
            warnings=warnings,
            workspace_resource_id=workspace_resource_id,
            allow_email_proxy=allow_email_proxy
            or (profile is not None and profile.profile.backend_preferences.allow_proxy),
            discover_workspaces=discover_workspaces,
            extras=_profile_collection_extras(profile),
        )
        evidence, collection_summaries, _result = collect_selected_evidence(
            ctx,
            registry,
            check_ids=[c.id for c in checks],
            profile_ids=tuple(profile.profile_ids) if profile is not None else (),
        )
    else:
        with GraphClient(auth) as client:
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
            owned = resolve_owned_capabilities(capabilities, skus)
            owned_set = set(owned)
            checks = _select_checks(profile=profile, workloads=workloads)
            workspace_resource_id = _maybe_discover_workspace(
                auth=auth,
                scan_mode=scan_mode,
                discover_workspaces=discover_workspaces,
                workspace_resource_id=workspace_resource_id,
                owned_set=owned_set,
                warnings=warnings,
            )
            ctx = ScanCollectionContext(
                scan_mode=scan_mode,
                auth=auth,
                client=client,
                skus=skus,
                warnings=warnings,
                workspace_resource_id=workspace_resource_id,
                allow_email_proxy=allow_email_proxy
                or (profile is not None and profile.profile.backend_preferences.allow_proxy),
                discover_workspaces=discover_workspaces,
                extras=_profile_collection_extras(profile),
            )
            evidence, collection_summaries, _result = collect_selected_evidence(
                ctx,
                registry,
                check_ids=[c.id for c in checks],
                profile_ids=tuple(profile.profile_ids) if profile is not None else (),
            )

    evidence["scanned_at"] = scan_time.isoformat()
    summaries = capability_summaries_for(capabilities, owned, skus)

    email_proxy = allow_email_proxy or (
        profile is not None and profile.profile.backend_preferences.allow_proxy
    )
    findings = [
        _evaluate_check(
            c,
            owned_set,
            evidence,
            strict_proxy=strict_proxy,
            allow_email_proxy=email_proxy,
            registry=registry,
        )
        for c in checks
    ]
    findings.sort(
        key=lambda f: (
            _STATUS_PRIORITY.get(f.status, 99),
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity.value, 9),
            f.check_id,
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
                    collection_summaries=collection_summaries,
                    profile_ids=profile.profile_ids,
                ),
            )
        )
        findings.sort(
            key=lambda f: (
                _STATUS_PRIORITY.get(f.status, 99),
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                    f.severity.value, 9
                ),
                f.check_id,
            )
        )

    live_pending = [f for f in findings if f.status == FindingStatus.SKIPPED]
    if scan_mode == "live" and live_pending:
        missing_eval = [
            f.check_id
            for f in live_pending
            if (f.evidence or {}).get("email_proxy_enabled") is not False
        ]
        unreadable = [
            f.check_id
            for f in live_pending
            if (f.evidence or {}).get("email_proxy_enabled") is False
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

    data_sources_used: list[str] = []
    for f in findings:
        data_sources_used.extend(f.data_sources)
    data_sources_used = sorted(set(data_sources_used))

    limitations = scan_level_limitations(findings, strict_proxy=strict_proxy)

    pack_scope = packs if packs is not None else DEFAULT_PACKS
    if profile is not None and packs is None:
        pack_scope = profile.profile.packs
    pack_values = [p.value if isinstance(p, CheckPack) else str(p) for p in pack_scope]
    moves = rank_moves(findings, limit=3, packs=pack_scope)
    rollup, outcomes = capability_rollup(
        load_checks(),
        findings,
        owned,
        summaries,
        packs_scanned=pack_scope,
    )
    exposed_ids = [f.check_id for f in findings if f.exposure_class == ExposureClass.EXPOSED]

    return ScanResult(
        version=__version__,
        tenant_id=tenant_id,
        tenant_display_name=tenant_display_name,
        tenant_slug=tenant_slug,
        scan_mode=scan_mode,
        auth_mode=auth.mode.value,
        scanned_at=scan_time.isoformat(),
        owned_capabilities=owned,
        capability_summaries=summaries,
        subscribed_skus=skus,
        findings=findings,
        profile_ids=profile.profile_ids if profile is not None else [],
        accepted_risks=(accepted_risk_annotations(profile.profile) if profile is not None else []),
        recommended_next_steps=recommended_next_steps_from_moves(moves),
        warnings=warnings,
        limitations=limitations,
        data_sources_used=data_sources_used,
        workspace_resource_id=workspace_resource_id or evidence.get("workspace_resource_id"),
        strict_proxy=strict_proxy,
        packs_scanned=pack_values,
        moves=moves,
        capability_rollup=rollup,
        capability_outcomes=outcomes,
        has_exposed=bool(exposed_ids),
        exposed_check_ids=sorted(set(exposed_ids)),
        collection_summaries=collection_summaries,
    )
