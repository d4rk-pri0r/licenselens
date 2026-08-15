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
from licenselens.collectors.access_reviews import (
    DEMO_ACCESS_REVIEWS,
    collect_access_review_definitions,
)
from licenselens.collectors.applications import (
    DEMO_APPLICATIONS_BUNDLE,
    collect_applications_bundle,
)
from licenselens.collectors.arm import subscription_id_from_resource_id
from licenselens.collectors.arm_selective import (
    DEMO_DEFENDER_PRICINGS,
    collect_defender_for_cloud_pricings,
    summarize_defender_for_cloud_pricings,
)
from licenselens.collectors.auth_methods import (
    DEMO_AUTH_METHODS_BUNDLE,
    collect_auth_methods_bundle,
)
from licenselens.collectors.authorization_policy import (
    DEMO_AUTHORIZATION_BUNDLE,
    collect_authorization_bundle,
)
from licenselens.collectors.collaboration_demo import demo_collaboration_evidence
from licenselens.collectors.conditional_access import DEMO_CA_POLICIES, collect_ca_policies
from licenselens.collectors.dns_records import (
    DEMO_DNS_RECORDS,
    collect_dns_evidence,
    system_resolver,
)
from licenselens.collectors.domains import DEMO_DOMAINS, collect_domains
from licenselens.collectors.exchange_demo import demo_exchange_evidence
from licenselens.collectors.guests import DEMO_GUESTS_BUNDLE, collect_guests_bundle
from licenselens.collectors.intune_policy import (
    DEMO_INTUNE_EVIDENCE_BUNDLE,
    collect_intune_evidence_bundle,
    intune_licensed_units,
)
from licenselens.collectors.mde import (
    DEMO_MDE_SUMMARY,
    collect_mde_machine_summary,
    mde_licensed_units,
)
from licenselens.collectors.mde_health import DEMO_MDE_HEALTH, collect_mde_health_summary
from licenselens.collectors.pim_policies import (
    DEMO_PIM_POLICIES_BUNDLE,
    collect_pim_policies_bundle,
)
from licenselens.collectors.power_data_demo import demo_power_data_evidence
from licenselens.collectors.privileged_roles import (
    DEMO_PRINCIPAL_DIRECTORY,
    DEMO_RECENT_SIGNIN_USER_IDS,
    DEMO_ROLE_ASSIGNMENTS,
    DEMO_ROLE_ELIGIBILITIES,
    collect_role_assignments,
    collect_role_eligibility_schedules,
    privileged_principal_ids,
)
from licenselens.collectors.purview import DEMO_DLP_BUNDLE, collect_purview_dlp_bundle
from licenselens.collectors.secure_score import (
    DEMO_SECURE_SCORE,
    collect_latest_secure_score,
    extract_control_scores,
)
from licenselens.collectors.security_alerts import (
    DEMO_SECURITY_ALERTS_BUNDLE,
    collect_security_alerts_bundle,
)
from licenselens.collectors.security_defaults import (
    DEMO_SECURITY_DEFAULTS,
    collect_security_defaults_policy,
)
from licenselens.collectors.sentinel import (
    DEMO_SENTINEL_RULES,
    DEMO_SENTINEL_UEBA,
    collect_sentinel_bundle,
)
from licenselens.collectors.sentinel_extended import (
    DEMO_SENTINEL_AUTOMATION_RULES,
    DEMO_SENTINEL_DATA_CONNECTORS,
    DEMO_SENTINEL_WORKSPACE,
    collect_sentinel_extended_bundle,
)
from licenselens.collectors.signins import (
    collect_directory_objects_by_ids,
    collect_recent_success_signin_user_ids,
)
from licenselens.collectors.skus import collect_subscribed_skus, collect_subscribed_skus_live
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
from licenselens.errors import AuthError, GraphError
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
    SubscribedSku,
    Workload,
)
from licenselens.schema_contracts import EvaluationMode

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


def _gather_evidence(
    *,
    scan_mode: str,
    client: GraphClient | None,
    auth: AuthContext,
    skus: list[SubscribedSku],
    warnings: list[str],
    workspace_resource_id: str | None = None,
) -> dict[str, Any]:
    """Collect shared evidence blobs for evaluators."""
    evidence: dict[str, Any] = {
        "signin_lookback_days": 90,
        "signin_sample_truncated": False,
    }

    if scan_mode == "dry_run":
        evidence["ca_policies"] = list(DEMO_CA_POLICIES)
        evidence["role_assignments"] = list(DEMO_ROLE_ASSIGNMENTS)
        evidence["role_eligibilities"] = list(DEMO_ROLE_ELIGIBILITIES)
        evidence["recent_signin_user_ids"] = set(DEMO_RECENT_SIGNIN_USER_IDS)
        evidence["principal_directory"] = dict(DEMO_PRINCIPAL_DIRECTORY)
        evidence["secure_score_controls"] = extract_control_scores(DEMO_SECURE_SCORE)
        evidence["mde_summary"] = dict(DEMO_MDE_SUMMARY)
        evidence["sentinel_rules"] = dict(DEMO_SENTINEL_RULES)
        evidence["sentinel_ueba"] = dict(DEMO_SENTINEL_UEBA)
        evidence["sentinel_data_connectors"] = dict(DEMO_SENTINEL_DATA_CONNECTORS)
        evidence["sentinel_automation_rules"] = dict(DEMO_SENTINEL_AUTOMATION_RULES)
        evidence["sentinel_workspace"] = dict(DEMO_SENTINEL_WORKSPACE)
        evidence["defender_for_cloud_pricings"] = dict(DEMO_DEFENDER_PRICINGS)
        evidence["purview_dlp"] = dict(DEMO_DLP_BUNDLE)
        evidence["security_defaults_policy"] = dict(DEMO_SECURITY_DEFAULTS)
        evidence["access_review_definitions"] = list(DEMO_ACCESS_REVIEWS)
        evidence["auth_methods_bundle"] = dict(DEMO_AUTH_METHODS_BUNDLE)
        evidence["applications_bundle"] = dict(DEMO_APPLICATIONS_BUNDLE)
        evidence["authorization_policy"] = dict(DEMO_AUTHORIZATION_BUNDLE["authorization_policy"])
        evidence["admin_consent_request_policy"] = dict(
            DEMO_AUTHORIZATION_BUNDLE["admin_consent_request_policy"]
        )
        evidence["guests_bundle"] = dict(DEMO_GUESTS_BUNDLE)
        evidence["pim_policies_bundle"] = dict(DEMO_PIM_POLICIES_BUNDLE)
        evidence["domains"] = list(DEMO_DOMAINS)
        evidence["break_glass_principal_ids"] = []
        evidence["approved_guest_domains"] = []
        evidence["dns_records"] = dict(DEMO_DNS_RECORDS)
        evidence.update(demo_exchange_evidence())
        evidence.update(demo_collaboration_evidence())
        evidence.update(demo_power_data_evidence())
        evidence["intune_bundle"] = dict(DEMO_INTUNE_EVIDENCE_BUNDLE)
        evidence["mde_health"] = dict(DEMO_MDE_HEALTH)
        evidence["security_alerts_bundle"] = dict(DEMO_SECURITY_ALERTS_BUNDLE)
        return evidence

    assert client is not None
    try:
        evidence["ca_policies"] = collect_ca_policies(client)
    except GraphError as exc:
        warnings.append(f"Conditional Access policies could not be read: {exc}")
        evidence["ca_policies_error"] = str(exc)

    try:
        evidence["role_assignments"] = collect_role_assignments(client)
    except GraphError as exc:
        warnings.append(f"Directory role assignments could not be read: {exc}")
        evidence["role_assignments_error"] = str(exc)

    try:
        evidence["role_eligibilities"] = collect_role_eligibility_schedules(client)
    except GraphError as exc:
        # PIM eligibility may 403 if not licensed / not consented — treat as empty + warn
        warnings.append(
            f"PIM role eligibility schedules could not be read (treating as none): {exc}"
        )
        evidence["role_eligibilities"] = []
        evidence["role_eligibilities_error"] = str(exc)

    assignments = list(evidence.get("role_assignments") or [])
    principal_ids = sorted(privileged_principal_ids(assignments))

    try:
        # Detect truncation: if we hit max pages, flag it
        max_pages = 15
        signin_ids = collect_recent_success_signin_user_ids(
            client, lookback_days=90, max_pages=max_pages
        )
        evidence["recent_signin_user_ids"] = signin_ids
        # Heuristic: very full page budget suggests truncation
        evidence["signin_sample_truncated"] = len(signin_ids) >= max_pages * 400
    except GraphError as exc:
        warnings.append(f"Sign-in logs could not be read: {exc}")
        evidence["recent_signin_error"] = str(exc)

    if principal_ids and "role_assignments_error" not in evidence:
        try:
            evidence["principal_directory"] = collect_directory_objects_by_ids(
                client, principal_ids
            )
        except GraphError as exc:
            warnings.append(f"Privileged principal directory lookup failed: {exc}")
            evidence["principal_directory_error"] = str(exc)
            evidence["principal_directory"] = {}

    # Defender pack signals
    try:
        score = collect_latest_secure_score(client)
        evidence["secure_score"] = score
        evidence["secure_score_controls"] = extract_control_scores(score)
    except GraphError as exc:
        warnings.append(f"Secure Score could not be read: {exc}")
        evidence["secure_score_controls_error"] = str(exc)
        evidence["secure_score_controls"] = []

    licensed = mde_licensed_units(skus)
    try:
        mde = collect_mde_machine_summary(auth)
        mde["licensed_units"] = licensed
        evidence["mde_summary"] = mde
    except (AuthError, GraphError) as exc:
        warnings.append(f"Defender for Endpoint inventory could not be read: {exc}")
        evidence["mde_summary_error"] = str(exc)

    try:
        evidence["intune_bundle"] = collect_intune_evidence_bundle(
            client, licensed_units=intune_licensed_units(skus)
        )
    except (AuthError, GraphError) as exc:
        warnings.append(f"Intune device management state could not be read: {exc}")
        evidence["intune_bundle_error"] = str(exc)

    try:
        evidence["mde_health"] = collect_mde_health_summary(auth)
    except (AuthError, GraphError) as exc:
        warnings.append(f"Defender for Endpoint sensor health could not be read: {exc}")
        evidence["mde_health_error"] = str(exc)

    try:
        evidence["security_alerts_bundle"] = collect_security_alerts_bundle(client)
    except GraphError as exc:
        warnings.append(f"Security incidents/alerts could not be read: {exc}")
        evidence["security_alerts_bundle_error"] = str(exc)

    # Sentinel pack
    if workspace_resource_id:
        try:
            bundle = collect_sentinel_bundle(auth, workspace_resource_id)
            evidence["sentinel_rules"] = bundle.get("sentinel_rules") or {}
            evidence["sentinel_ueba"] = bundle.get("sentinel_ueba") or {}
            evidence["workspace_resource_id"] = bundle.get("workspace_resource_id")
        except (AuthError, GraphError) as exc:
            warnings.append(f"Sentinel workspace could not be read: {exc}")
            evidence["sentinel_rules_error"] = str(exc)
            evidence["sentinel_ueba_error"] = str(exc)

        try:
            extended = collect_sentinel_extended_bundle(auth, workspace_resource_id)
            evidence.update(
                {key: value for key, value in extended.items() if key != "workspace_resource_id"}
            )
        except (AuthError, GraphError) as exc:
            warnings.append(f"Sentinel connectors/automation could not be read: {exc}")

        sub = subscription_id_from_resource_id(workspace_resource_id)
        if sub:
            try:
                from licenselens.collectors.arm import ArmClient

                with ArmClient(auth) as arm:
                    pricings = collect_defender_for_cloud_pricings(arm, sub)
                evidence["defender_for_cloud_pricings"] = summarize_defender_for_cloud_pricings(
                    pricings, sub
                )
            except (AuthError, GraphError) as exc:
                warnings.append(f"Defender for Cloud plan pricing could not be read: {exc}")
                evidence["defender_for_cloud_pricings_error"] = str(exc)
        else:
            evidence["defender_for_cloud_pricings_error"] = (
                "No Azure subscription could be derived from the workspace resource ID."
            )
    else:
        evidence["sentinel_workspace_missing"] = True
        warnings.append(
            "No Sentinel workspace provided (--workspace-resource-id). "
            "Sentinel checks will report an error until a workspace is supplied."
        )
        evidence["defender_for_cloud_pricings_error"] = (
            "Selective-Azure checks require --workspace-resource-id "
            "(or subscription/resource-group/workspace-name)."
        )

    # Purview DLP (Secure Score proxy)
    controls = list(evidence.get("secure_score_controls") or [])
    if evidence.get("secure_score_controls_error") and not controls:
        evidence["purview_dlp_error"] = str(evidence["secure_score_controls_error"])
    else:
        evidence["purview_dlp"] = collect_purview_dlp_bundle(client, controls)

    # Security defaults policy state
    try:
        evidence["security_defaults_policy"] = collect_security_defaults_policy(client)
    except GraphError as exc:
        warnings.append(f"Security defaults policy could not be read: {exc}")
        evidence["security_defaults_policy_error"] = str(exc)
        evidence["security_defaults_policy"] = {}

    # Access review definitions
    try:
        evidence["access_review_definitions"] = collect_access_review_definitions(client)
    except GraphError as exc:
        warnings.append(f"Access review definitions could not be read: {exc}")
        evidence["access_review_definitions_error"] = str(exc)
        evidence["access_review_definitions"] = []

    evidence.setdefault("break_glass_principal_ids", [])
    evidence.setdefault("approved_guest_domains", [])
    try:
        evidence["auth_methods_bundle"] = collect_auth_methods_bundle(client)
    except GraphError as exc:
        warnings.append(f"Authentication methods policy could not be read: {exc}")
        evidence["auth_methods_bundle_error"] = str(exc)
        evidence["auth_methods_bundle"] = {}
    try:
        evidence["applications_bundle"] = collect_applications_bundle(client)
    except GraphError as exc:
        warnings.append(f"Applications inventory could not be read: {exc}")
        evidence["applications_bundle_error"] = str(exc)
        evidence["applications_bundle"] = {}
    try:
        authz = collect_authorization_bundle(client)
        evidence["authorization_policy"] = authz.get("authorization_policy") or {}
        evidence["admin_consent_request_policy"] = authz.get("admin_consent_request_policy") or {}
    except GraphError as exc:
        warnings.append(f"Authorization policy could not be read: {exc}")
        evidence["authorization_policy_error"] = str(exc)
        evidence["authorization_policy"] = {}
        evidence["admin_consent_request_policy"] = {}
    try:
        evidence["guests_bundle"] = collect_guests_bundle(client)
    except GraphError as exc:
        warnings.append(f"Guest / cross-tenant settings could not be read: {exc}")
        evidence["guests_bundle_error"] = str(exc)
        evidence["guests_bundle"] = {}
    try:
        evidence["pim_policies_bundle"] = collect_pim_policies_bundle(client)
    except GraphError as exc:
        warnings.append(f"PIM role management policies could not be read: {exc}")
        evidence["pim_policies_bundle_error"] = str(exc)
        evidence["pim_policies_bundle"] = {}
    try:
        evidence["domains"] = collect_domains(client)
    except GraphError as exc:
        warnings.append(f"Domain password settings could not be read: {exc}")
        evidence["domains_error"] = str(exc)
        evidence["domains"] = []

    # Exchange Online / SCC via allowlisted PowerShell bridge (best-effort).
    # Direct reads supersede Secure Score email proxy when usable.
    try:
        from licenselens.collectors.exchange import (
            ExchangeCollectOptions,
            collect_exchange_evidence,
        )
        from licenselens.collectors.exchange_models import EXCHANGE_ADAPTERS

        exo = collect_exchange_evidence(ExchangeCollectOptions(adapters=EXCHANGE_ADAPTERS))
        evidence.update(exo)
        if not exo.get("exchange_threat_usable"):
            warnings.append(
                "Exchange Online PowerShell threat policies were not fully readable; "
                "MDO check stays skipped unless --allow-email-proxy is set."
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Exchange Online PowerShell collectors unavailable: {exc}")
        evidence["exchange_threat_usable"] = False
        evidence["exchange_collect_error"] = str(exc)

    # Email-authentication DNS checks (SPF/DMARC) — bounded system resolver.
    try:
        tenant_domains = list(evidence.get("domains") or [])
        evidence["dns_records"] = collect_dns_evidence(tenant_domains, system_resolver())
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"DNS email-authentication checks failed: {exc}")
        evidence["dns_records_error"] = str(exc)
        evidence["dns_records"] = {"domains": [], "records": {}}

    # Teams + SharePoint/OneDrive via allowlisted PowerShell bridge (best-effort).
    try:
        from licenselens.collectors.collaboration import (
            CollaborationCollectOptions,
            collect_collaboration_evidence,
        )

        collab = collect_collaboration_evidence(CollaborationCollectOptions())
        evidence.update(collab)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Collaboration PowerShell collectors unavailable: {exc}")
        evidence["collaboration_collect_error"] = str(exc)

    # Power Platform + Power BI + Purview via allowlisted PowerShell bridge (best-effort).
    try:
        from licenselens.collectors.power_data import (
            PowerDataCollectOptions,
            collect_power_data_evidence,
        )

        power = collect_power_data_evidence(PowerDataCollectOptions())
        evidence.update(power)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Power Platform / Power BI PowerShell collectors unavailable: {exc}")
        evidence["power_data_collect_error"] = str(exc)

    return evidence


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
    evidence: dict[str, Any] = {}

    if scan_mode == "dry_run":
        skus = collect_subscribed_skus(auth, dry_run=True)
        evidence = _gather_evidence(
            scan_mode=scan_mode,
            client=None,
            auth=auth,
            skus=skus,
            warnings=warnings,
            workspace_resource_id=workspace_resource_id,
        )
        tenant_id = tenant_id or "00000000-0000-0000-0000-000000000000"
        tenant_display_name = tenant_display_name or "Contoso Demo (dry-run)"
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
            evidence = _gather_evidence(
                scan_mode=scan_mode,
                client=client,
                auth=auth,
                skus=skus,
                warnings=warnings,
                workspace_resource_id=workspace_resource_id,
            )

    evidence["scanned_at"] = scan_time.isoformat()

    owned = resolve_owned_capabilities(capabilities, skus)
    owned_set = set(owned)
    summaries = capability_summaries_for(capabilities, owned, skus)

    if profile is not None:
        bg_ids: list[str] = []
        approved_domains: list[str] = list(profile.profile.sensitive_domains)
        for exclusion in profile.profile.exclusions:
            if str(getattr(exclusion, "kind", "general")).lower() == "break_glass":
                bg_ids.extend(str(pid) for pid in exclusion.principal_ids if pid)
            if not exclusion.reason.strip():
                continue
        evidence["break_glass_principal_ids"] = sorted(set(bg_ids))
        evidence["approved_guest_domains"] = sorted(set(approved_domains))
        evidence["approved_partner_domains"] = sorted(set(profile.profile.sensitive_domains))
        evidence["sensitive_users"] = sorted(set(profile.profile.sensitive_users))
        evidence["sensitive_domains"] = sorted(set(profile.profile.sensitive_domains))
        evidence["allowed_forwarding_domains"] = sorted(
            set(profile.profile.allowed_forwarding_domains)
        )
        evidence["dmarc_agency_contact"] = profile.profile.dmarc_agency_contact.strip()
        evidence["dmarc_federal_contact"] = profile.profile.dmarc_federal_contact.strip()

    checks = [c for c in load_checks() if c.enabled]
    if profile is not None:
        selected_check_ids = set(profile.selected_check_ids)
        checks = [c for c in checks if c.id in selected_check_ids]
    if workloads:
        wanted = set(workloads)
        checks = [c for c in checks if c.workload in wanted]

    # Optional workspace auto-discover when Sentinel owned and no workspace given
    if (
        scan_mode == "live"
        and discover_workspaces
        and not workspace_resource_id
        and "microsoft_sentinel" in owned_set
    ):
        try:
            from licenselens.collectors.workspace_discover import discover_sentinel_workspaces

            discovered = discover_sentinel_workspaces(auth)
            if len(discovered) == 1:
                workspace_resource_id = discovered[0]
                warnings.append(f"Auto-discovered Sentinel workspace: {workspace_resource_id}")
                # Re-collect sentinel evidence only
                from licenselens.collectors.sentinel import collect_sentinel_bundle

                bundle = collect_sentinel_bundle(auth, workspace_resource_id)
                evidence["sentinel_rules"] = bundle.get("sentinel_rules") or {}
                evidence["sentinel_ueba"] = bundle.get("sentinel_ueba") or {}
                try:
                    extended = collect_sentinel_extended_bundle(auth, workspace_resource_id)
                    evidence.update(
                        {
                            key: value
                            for key, value in extended.items()
                            if key != "workspace_resource_id"
                        }
                    )
                except (AuthError, GraphError) as exc:
                    warnings.append(f"Sentinel connectors/automation could not be read: {exc}")
                sub = subscription_id_from_resource_id(workspace_resource_id)
                if sub:
                    try:
                        from licenselens.collectors.arm import ArmClient

                        with ArmClient(auth) as arm:
                            pricings = collect_defender_for_cloud_pricings(arm, sub)
                        evidence["defender_for_cloud_pricings"] = (
                            summarize_defender_for_cloud_pricings(pricings, sub)
                        )
                    except (AuthError, GraphError) as exc:
                        warnings.append(f"Defender for Cloud plan pricing could not be read: {exc}")
                        evidence["defender_for_cloud_pricings_error"] = str(exc)
                evidence.pop("sentinel_workspace_missing", None)
            elif len(discovered) > 1:
                warnings.append(
                    f"Found {len(discovered)} possible Sentinel workspaces; "
                    "pass --workspace-resource-id explicitly (refusing to guess)."
                )
            else:
                warnings.append("Workspace auto-discover found no Sentinel workspaces.")
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Workspace auto-discover failed: {exc}")

    findings = [
        _evaluate_check(
            c,
            owned_set,
            evidence,
            strict_proxy=strict_proxy,
            allow_email_proxy=(
                allow_email_proxy
                or (profile is not None and profile.profile.backend_preferences.allow_proxy)
            ),
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
                    collection_summaries=[],
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
    )
