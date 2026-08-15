"""Bind registered collector factories to live/dry-run ScanCollectionContext closures."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

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
from licenselens.collectors.contracts import (
    CheckId,
    CollectionMetadata,
    CollectorId,
    EvidenceEnvelope,
    EvidenceHealth,
    EvidenceKey,
    PaginationMetadata,
)
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
from licenselens.engine.collection_context import ScanCollectionContext
from licenselens.engine.planner import (
    CheckEvidenceRequirement,
    CollectionContext,
    CollectionResult,
    CollectorSpec,
    EvidencePlanner,
)
from licenselens.engine.registry import AssessmentRegistry
from licenselens.errors import AuthError, GraphError
from licenselens.schema_contracts import CollectionStatus, CollectionSummary

type EvidenceCollectorFn = Callable[
    [ScanCollectionContext, CollectionContext],
    EvidenceEnvelope,
]

# Keys whose envelope value is a multi-field dict that must be merged into evidence.
_EXPAND_VALUE_KEYS = frozenset(
    {
        "exchange_bundle",
        "collaboration_bundle",
        "power_data_bundle",
    }
)

_ERROR_ALIASES: dict[str, str] = {
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

# Canonical dependency edges for the runtime DAG (overrides factory chain order).
_RUNTIME_DEPENDS: dict[str, tuple[str, ...]] = {
    "principal_directory": ("role_assignments",),
    "purview_dlp": ("secure_score_controls",),
    "dns_records": ("domains",),
    "admin_consent_request_policy": (),
    "approved_guest_domains": (),
    "break_glass_principal_ids": (),
}


def _meta(source: str, items: int = 0, *, truncated: bool = False) -> CollectionMetadata:
    return CollectionMetadata(
        source=source,
        items_collected=items,
        pagination=PaginationMetadata(
            pages_read=1 if items else 0,
            max_pages=1,
            next_link_seen=truncated,
        ),
    )


def _ok(
    key: str,
    value: Any,
    *,
    source: str = "",
    items: int = 0,
    truncated: bool = False,
) -> EvidenceEnvelope:
    ek = EvidenceKey(key)
    if truncated:
        return EvidenceEnvelope.truncated(
            ek,
            reason="page budget exhausted",
            metadata=_meta(source, items, truncated=True),
        )
    return EvidenceEnvelope(
        key=ek,
        health=EvidenceHealth.OK,
        value=value,
        metadata=_meta(source, items),
    )


def _denied(key: str, reason: str) -> EvidenceEnvelope:
    return EvidenceEnvelope.denied(EvidenceKey(key), reason=reason)


def _error(key: str, reason: str) -> EvidenceEnvelope:
    return EvidenceEnvelope.error(EvidenceKey(key), reason=reason)


def _unavailable(key: str, reason: str) -> EvidenceEnvelope:
    return EvidenceEnvelope.unavailable(EvidenceKey(key), reason=reason)


def _is_denied(exc: BaseException) -> bool:
    text = str(exc)
    return "403" in text or "Authorization_RequestDenied" in text or "AccessDenied" in text


def _graph_failure(
    key: str,
    exc: BaseException,
    warn: str,
    ctx: ScanCollectionContext,
) -> EvidenceEnvelope:
    ctx.warn(warn)
    reason = str(exc)
    if _is_denied(exc):
        return _denied(key, reason)
    return _error(key, reason)


def _envelope_value(context: CollectionContext, key: str) -> Any:
    env = context.envelopes.get(EvidenceKey(key))
    if env is None or not env.is_usable:
        return None
    return env.value


def _collect_ca_policies(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "ca_policies"
    if ctx.is_dry_run:
        return _ok(key, list(DEMO_CA_POLICIES), source="demo", items=len(DEMO_CA_POLICIES))
    assert ctx.client is not None
    try:
        policies = collect_ca_policies(ctx.client)
        return _ok(key, policies, source="graph.identity", items=len(policies))
    except GraphError as exc:
        return _graph_failure(
            key,
            exc,
            f"Conditional Access policies could not be read: {exc}",
            ctx,
        )


def _collect_role_assignments(
    ctx: ScanCollectionContext,
    _pc: CollectionContext,
) -> EvidenceEnvelope:
    key = "role_assignments"
    if ctx.is_dry_run:
        return _ok(
            key,
            list(DEMO_ROLE_ASSIGNMENTS),
            source="demo",
            items=len(DEMO_ROLE_ASSIGNMENTS),
        )
    assert ctx.client is not None
    try:
        assignments = collect_role_assignments(ctx.client)
        return _ok(key, assignments, source="graph.directoryRoles", items=len(assignments))
    except GraphError as exc:
        return _graph_failure(
            key,
            exc,
            f"Directory role assignments could not be read: {exc}",
            ctx,
        )


def _collect_role_eligibilities(
    ctx: ScanCollectionContext,
    _pc: CollectionContext,
) -> EvidenceEnvelope:
    key = "role_eligibilities"
    if ctx.is_dry_run:
        return _ok(
            key, list(DEMO_ROLE_ELIGIBILITIES), source="demo", items=len(DEMO_ROLE_ELIGIBILITIES)
        )
    assert ctx.client is not None
    try:
        elig = collect_role_eligibility_schedules(ctx.client)
        return _ok(key, elig, source="graph.roleManagement", items=len(elig))
    except GraphError as exc:
        # PIM eligibility may 403 if not licensed / not consented — treat as empty + warn.
        ctx.warn(f"PIM role eligibility schedules could not be read (treating as none): {exc}")
        return _ok(key, [], source="graph.roleManagement", items=0)


def _collect_recent_signins(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "recent_signin_user_ids"
    if ctx.is_dry_run:
        ids = set(DEMO_RECENT_SIGNIN_USER_IDS)
        ctx.extras["signin_lookback_days"] = 90
        ctx.extras["signin_sample_truncated"] = False
        return _ok(key, ids, source="demo", items=len(ids))
    assert ctx.client is not None
    max_pages = 15
    try:
        signin_ids = collect_recent_success_signin_user_ids(
            ctx.client, lookback_days=90, max_pages=max_pages
        )
        truncated = len(signin_ids) >= max_pages * 400
        ctx.extras["signin_lookback_days"] = 90
        ctx.extras["signin_sample_truncated"] = truncated
        return _ok(
            key,
            signin_ids,
            source="graph.auditLogs.signIns",
            items=len(signin_ids),
            truncated=truncated,
        )
    except GraphError as exc:
        return _graph_failure(key, exc, f"Sign-in logs could not be read: {exc}", ctx)


def _collect_principal_directory(
    ctx: ScanCollectionContext, pc: CollectionContext
) -> EvidenceEnvelope:
    key = "principal_directory"
    if ctx.is_dry_run:
        return _ok(
            key,
            dict(DEMO_PRINCIPAL_DIRECTORY),
            source="demo",
            items=len(DEMO_PRINCIPAL_DIRECTORY),
        )
    assert ctx.client is not None
    assignments = list(_envelope_value(pc, "role_assignments") or [])
    principal_ids = sorted(privileged_principal_ids(assignments))
    if not principal_ids:
        return _ok(key, {}, source="graph.directoryObjects", items=0)
    try:
        directory = collect_directory_objects_by_ids(ctx.client, principal_ids)
        return _ok(key, directory, source="graph.directoryObjects", items=len(directory))
    except GraphError as exc:
        return _graph_failure(key, exc, f"Privileged principal directory lookup failed: {exc}", ctx)


def _collect_secure_score_controls(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "secure_score_controls"
    if ctx.is_dry_run:
        controls = extract_control_scores(DEMO_SECURE_SCORE)
        return _ok(key, controls, source="demo", items=len(controls))
    assert ctx.client is not None
    try:
        score = collect_latest_secure_score(ctx.client)
        controls = extract_control_scores(score)
        ctx.extras["secure_score"] = score
        return _ok(key, controls, source="graph.security.secureScores", items=len(controls))
    except GraphError as exc:
        return _graph_failure(key, exc, f"Secure Score could not be read: {exc}", ctx)


def _collect_mde_summary(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "mde_summary"
    licensed = mde_licensed_units(ctx.skus)
    if ctx.is_dry_run:
        summary = dict(DEMO_MDE_SUMMARY)
        summary["licensed_units"] = licensed
        return _ok(key, summary, source="demo", items=int(summary.get("sample_size") or 0))
    try:
        mde = collect_mde_machine_summary(ctx.auth)
        mde["licensed_units"] = licensed
        return _ok(key, mde, source="mde.machines", items=int(mde.get("sample_size") or 0))
    except (AuthError, GraphError) as exc:
        return _graph_failure(
            key, exc, f"Defender for Endpoint inventory could not be read: {exc}", ctx
        )


def _collect_mde_health(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "mde_health"
    if ctx.is_dry_run:
        return _ok(key, dict(DEMO_MDE_HEALTH), source="demo")
    try:
        health = collect_mde_health_summary(ctx.auth)
        return _ok(key, health, source="mde.machineHealth")
    except (AuthError, GraphError) as exc:
        return _graph_failure(
            key, exc, f"Defender for Endpoint sensor health could not be read: {exc}", ctx
        )


def _collect_intune_bundle(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "intune_bundle"
    if ctx.is_dry_run:
        return _ok(key, dict(DEMO_INTUNE_EVIDENCE_BUNDLE), source="demo")
    assert ctx.client is not None
    try:
        bundle = collect_intune_evidence_bundle(
            ctx.client, licensed_units=intune_licensed_units(ctx.skus)
        )
        return _ok(key, bundle, source="graph.deviceManagement")
    except (AuthError, GraphError) as exc:
        return _graph_failure(
            key, exc, f"Intune device management state could not be read: {exc}", ctx
        )


def _collect_security_alerts(
    ctx: ScanCollectionContext,
    _pc: CollectionContext,
) -> EvidenceEnvelope:
    key = "security_alerts_bundle"
    if ctx.is_dry_run:
        return _ok(key, dict(DEMO_SECURITY_ALERTS_BUNDLE), source="demo")
    assert ctx.client is not None
    try:
        bundle = collect_security_alerts_bundle(ctx.client)
        return _ok(key, bundle, source="graph.security")
    except GraphError as exc:
        return _graph_failure(key, exc, f"Security incidents/alerts could not be read: {exc}", ctx)


def _workspace_missing(ctx: ScanCollectionContext) -> EvidenceEnvelope | None:
    if ctx.workspace_resource_id:
        return None
    ctx.extras["sentinel_workspace_missing"] = True
    reason = (
        "No Sentinel workspace provided (--workspace-resource-id). "
        "Sentinel checks will report an error until a workspace is supplied."
    )
    if "No Sentinel workspace provided" not in " ".join(ctx.warnings):
        ctx.warn(reason)
    return _unavailable("sentinel_rules", reason)


def _collect_sentinel_rules(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "sentinel_rules"
    if ctx.is_dry_run:
        return _ok(key, dict(DEMO_SENTINEL_RULES), source="demo")
    missing = _workspace_missing(ctx)
    if missing is not None:
        return _unavailable(key, missing.reason)
    assert ctx.workspace_resource_id is not None
    try:
        bundle = collect_sentinel_bundle(ctx.auth, ctx.workspace_resource_id)
        ctx.extras["workspace_resource_id"] = bundle.get("workspace_resource_id")
        # Cache UEBA from the same bundle for the sibling collector when present.
        if bundle.get("sentinel_ueba") is not None:
            ctx.extras["_sentinel_ueba_cache"] = bundle.get("sentinel_ueba") or {}
        return _ok(key, bundle.get("sentinel_rules") or {}, source="arm.sentinel")
    except (AuthError, GraphError) as exc:
        return _graph_failure(key, exc, f"Sentinel workspace could not be read: {exc}", ctx)


def _collect_sentinel_ueba(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "sentinel_ueba"
    if ctx.is_dry_run:
        return _ok(key, dict(DEMO_SENTINEL_UEBA), source="demo")
    if not ctx.workspace_resource_id:
        ctx.extras["sentinel_workspace_missing"] = True
        return _unavailable(key, "No Sentinel workspace provided (--workspace-resource-id).")
    cached = ctx.extras.get("_sentinel_ueba_cache")
    if cached is not None:
        return _ok(key, dict(cached), source="arm.sentinel")
    try:
        bundle = collect_sentinel_bundle(ctx.auth, ctx.workspace_resource_id)
        return _ok(key, bundle.get("sentinel_ueba") or {}, source="arm.sentinel")
    except (AuthError, GraphError) as exc:
        # Preserve prior behavior: UEBA may fail independently while rules succeed.
        ctx.warn(f"Sentinel workspace could not be read: {exc}")
        return _error(key, str(exc))


def _collect_sentinel_extended_key(
    ctx: ScanCollectionContext,
    _pc: CollectionContext,
    *,
    key: str,
    demo: Mapping[str, Any],
) -> EvidenceEnvelope:
    if ctx.is_dry_run:
        return _ok(key, dict(demo), source="demo")
    if not ctx.workspace_resource_id:
        ctx.extras["sentinel_workspace_missing"] = True
        return _unavailable(key, "No Sentinel workspace provided (--workspace-resource-id).")
    cache_key = "_sentinel_extended_cache"
    extended = ctx.extras.get(cache_key)
    if extended is None:
        try:
            extended = collect_sentinel_extended_bundle(ctx.auth, ctx.workspace_resource_id)
            ctx.extras[cache_key] = extended
        except (AuthError, GraphError) as exc:
            ctx.warn(f"Sentinel connectors/automation could not be read: {exc}")
            return _error(key, str(exc))
    value = extended.get(key)
    err = extended.get(f"{key}_error")
    if err and value is None:
        return _error(key, str(err))
    return _ok(key, value if value is not None else {}, source="arm.sentinel")


def _collect_sentinel_data_connectors(
    ctx: ScanCollectionContext, pc: CollectionContext
) -> EvidenceEnvelope:
    return _collect_sentinel_extended_key(
        ctx, pc, key="sentinel_data_connectors", demo=DEMO_SENTINEL_DATA_CONNECTORS
    )


def _collect_sentinel_automation_rules(
    ctx: ScanCollectionContext, pc: CollectionContext
) -> EvidenceEnvelope:
    return _collect_sentinel_extended_key(
        ctx, pc, key="sentinel_automation_rules", demo=DEMO_SENTINEL_AUTOMATION_RULES
    )


def _collect_sentinel_workspace(
    ctx: ScanCollectionContext, pc: CollectionContext
) -> EvidenceEnvelope:
    return _collect_sentinel_extended_key(
        ctx, pc, key="sentinel_workspace", demo=DEMO_SENTINEL_WORKSPACE
    )


def _collect_defender_pricings(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "defender_for_cloud_pricings"
    if ctx.is_dry_run:
        return _ok(key, dict(DEMO_DEFENDER_PRICINGS), source="demo")
    if not ctx.workspace_resource_id:
        reason = (
            "Selective-Azure checks require --workspace-resource-id "
            "(or subscription/resource-group/workspace-name)."
        )
        return _error(key, reason)
    sub = subscription_id_from_resource_id(ctx.workspace_resource_id)
    if not sub:
        return _error(
            key,
            "No Azure subscription could be derived from the workspace resource ID.",
        )
    try:
        from licenselens.collectors.arm import ArmClient

        with ArmClient(ctx.auth) as arm:
            pricings = collect_defender_for_cloud_pricings(arm, sub)
        summary = summarize_defender_for_cloud_pricings(pricings, sub)
        return _ok(key, summary, source="arm.security.pricings")
    except (AuthError, GraphError) as exc:
        return _graph_failure(
            key, exc, f"Defender for Cloud plan pricing could not be read: {exc}", ctx
        )


def _collect_purview_dlp(ctx: ScanCollectionContext, pc: CollectionContext) -> EvidenceEnvelope:
    key = "purview_dlp"
    if ctx.is_dry_run:
        return _ok(key, dict(DEMO_DLP_BUNDLE), source="demo")
    controls = list(_envelope_value(pc, "secure_score_controls") or [])
    score_env = pc.envelopes.get(EvidenceKey("secure_score_controls"))
    if score_env is not None and not score_env.is_usable and not controls:
        return _error(key, score_env.reason or "secure score controls unavailable")
    assert ctx.client is not None
    try:
        bundle = collect_purview_dlp_bundle(ctx.client, controls)
        return _ok(key, bundle, source="graph.security.secureScores")
    except GraphError as exc:
        return _graph_failure(key, exc, f"Purview DLP proxy could not be read: {exc}", ctx)


def _collect_security_defaults(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "security_defaults_policy"
    if ctx.is_dry_run:
        return _ok(key, dict(DEMO_SECURITY_DEFAULTS), source="demo")
    assert ctx.client is not None
    try:
        policy = collect_security_defaults_policy(ctx.client)
        return _ok(key, policy, source="graph.policies.identitySecurityDefaultsEnforcementPolicy")
    except GraphError as exc:
        return _graph_failure(key, exc, f"Security defaults policy could not be read: {exc}", ctx)


def _collect_access_reviews(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "access_review_definitions"
    if ctx.is_dry_run:
        return _ok(key, list(DEMO_ACCESS_REVIEWS), source="demo", items=len(DEMO_ACCESS_REVIEWS))
    assert ctx.client is not None
    try:
        definitions = collect_access_review_definitions(ctx.client)
        return _ok(key, definitions, source="graph.identityGovernance", items=len(definitions))
    except GraphError as exc:
        return _graph_failure(key, exc, f"Access review definitions could not be read: {exc}", ctx)


def _collect_auth_methods(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "auth_methods_bundle"
    if ctx.is_dry_run:
        return _ok(key, dict(DEMO_AUTH_METHODS_BUNDLE), source="demo")
    assert ctx.client is not None
    try:
        bundle = collect_auth_methods_bundle(ctx.client)
        return _ok(key, bundle, source="graph.policies.authenticationMethodsPolicy")
    except GraphError as exc:
        return _graph_failure(
            key, exc, f"Authentication methods policy could not be read: {exc}", ctx
        )


def _collect_applications(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "applications_bundle"
    if ctx.is_dry_run:
        return _ok(key, dict(DEMO_APPLICATIONS_BUNDLE), source="demo")
    assert ctx.client is not None
    try:
        bundle = collect_applications_bundle(ctx.client)
        return _ok(key, bundle, source="graph.applications")
    except GraphError as exc:
        return _graph_failure(key, exc, f"Applications inventory could not be read: {exc}", ctx)


def _collect_authorization_policy(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "authorization_policy"
    if ctx.is_dry_run:
        return _ok(
            key,
            dict(DEMO_AUTHORIZATION_BUNDLE["authorization_policy"]),
            source="demo",
        )
    assert ctx.client is not None
    try:
        authz = collect_authorization_bundle(ctx.client)
        ctx.extras["_admin_consent_request_policy_cache"] = (
            authz.get("admin_consent_request_policy") or {}
        )
        return _ok(
            key,
            authz.get("authorization_policy") or {},
            source="graph.policies.authorizationPolicy",
        )
    except GraphError as exc:
        return _graph_failure(key, exc, f"Authorization policy could not be read: {exc}", ctx)


def _collect_admin_consent_policy(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "admin_consent_request_policy"
    if ctx.is_dry_run:
        return _ok(
            key,
            dict(DEMO_AUTHORIZATION_BUNDLE["admin_consent_request_policy"]),
            source="demo",
        )
    cached = ctx.extras.get("_admin_consent_request_policy_cache")
    if cached is not None:
        return _ok(key, dict(cached), source="graph.policies.adminConsentRequestPolicy")
    assert ctx.client is not None
    try:
        authz = collect_authorization_bundle(ctx.client)
        return _ok(
            key,
            authz.get("admin_consent_request_policy") or {},
            source="graph.policies.adminConsentRequestPolicy",
        )
    except GraphError as exc:
        return _graph_failure(key, exc, f"Authorization policy could not be read: {exc}", ctx)


def _collect_guests(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "guests_bundle"
    if ctx.is_dry_run:
        return _ok(key, dict(DEMO_GUESTS_BUNDLE), source="demo")
    assert ctx.client is not None
    try:
        bundle = collect_guests_bundle(ctx.client)
        return _ok(key, bundle, source="graph.policies.crossTenantAccess")
    except GraphError as exc:
        return _graph_failure(
            key, exc, f"Guest / cross-tenant settings could not be read: {exc}", ctx
        )


def _collect_pim_policies(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "pim_policies_bundle"
    if ctx.is_dry_run:
        return _ok(key, dict(DEMO_PIM_POLICIES_BUNDLE), source="demo")
    assert ctx.client is not None
    try:
        bundle = collect_pim_policies_bundle(ctx.client)
        return _ok(key, bundle, source="graph.roleManagement.policies")
    except GraphError as exc:
        return _graph_failure(
            key, exc, f"PIM role management policies could not be read: {exc}", ctx
        )


def _collect_domains(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "domains"
    if ctx.is_dry_run:
        return _ok(key, list(DEMO_DOMAINS), source="demo", items=len(DEMO_DOMAINS))
    assert ctx.client is not None
    try:
        domains = collect_domains(ctx.client)
        return _ok(key, domains, source="graph.domains", items=len(domains))
    except GraphError as exc:
        return _graph_failure(key, exc, f"Domain password settings could not be read: {exc}", ctx)


def _collect_break_glass(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "break_glass_principal_ids"
    value = list(ctx.extras.get("break_glass_principal_ids") or [])
    return _ok(key, value, source="profile", items=len(value))


def _collect_approved_guest_domains(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "approved_guest_domains"
    value = list(ctx.extras.get("approved_guest_domains") or [])
    return _ok(key, value, source="profile", items=len(value))


def _collect_exchange(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "exchange_bundle"
    if ctx.is_dry_run:
        payload = demo_exchange_evidence()
        return _ok(key, payload, source="demo")
    try:
        from licenselens.collectors.exchange import (
            ExchangeCollectOptions,
            collect_exchange_evidence,
        )
        from licenselens.collectors.exchange_models import EXCHANGE_ADAPTERS

        exo = collect_exchange_evidence(ExchangeCollectOptions(adapters=EXCHANGE_ADAPTERS))
        if not exo.get("exchange_threat_usable"):
            ctx.warn(
                "Exchange Online PowerShell threat policies were not fully readable; "
                "MDO check stays skipped unless --allow-email-proxy is set."
            )
        return _ok(key, exo, source="powershell.exchange")
    except Exception as exc:  # noqa: BLE001
        ctx.warn(f"Exchange Online PowerShell collectors unavailable: {exc}")
        return _error(key, str(exc))


def _collect_dns(ctx: ScanCollectionContext, pc: CollectionContext) -> EvidenceEnvelope:
    key = "dns_records"
    if ctx.is_dry_run:
        return _ok(key, dict(DEMO_DNS_RECORDS), source="demo")
    try:
        tenant_domains = list(_envelope_value(pc, "domains") or [])
        records = collect_dns_evidence(tenant_domains, system_resolver())
        return _ok(key, records, source="dns.system")
    except Exception as exc:  # noqa: BLE001
        ctx.warn(f"DNS email-authentication checks failed: {exc}")
        return _error(key, str(exc))


def _collect_collaboration(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "collaboration_bundle"
    if ctx.is_dry_run:
        return _ok(key, demo_collaboration_evidence(), source="demo")
    try:
        from licenselens.collectors.collaboration import (
            CollaborationCollectOptions,
            collect_collaboration_evidence,
        )

        collab = collect_collaboration_evidence(CollaborationCollectOptions())
        return _ok(key, collab, source="powershell.collaboration")
    except Exception as exc:  # noqa: BLE001
        ctx.warn(f"Collaboration PowerShell collectors unavailable: {exc}")
        return _error(key, str(exc))


def _collect_power_data(ctx: ScanCollectionContext, _pc: CollectionContext) -> EvidenceEnvelope:
    key = "power_data_bundle"
    if ctx.is_dry_run:
        return _ok(key, demo_power_data_evidence(), source="demo")
    try:
        from licenselens.collectors.power_data import (
            PowerDataCollectOptions,
            collect_power_data_evidence,
        )

        power = collect_power_data_evidence(PowerDataCollectOptions())
        return _ok(key, power, source="powershell.power_data")
    except Exception as exc:  # noqa: BLE001
        ctx.warn(f"Power Platform / Power BI PowerShell collectors unavailable: {exc}")
        return _error(key, str(exc))


_COLLECTORS: dict[str, EvidenceCollectorFn] = {
    "ca_policies": _collect_ca_policies,
    "role_assignments": _collect_role_assignments,
    "role_eligibilities": _collect_role_eligibilities,
    "recent_signin_user_ids": _collect_recent_signins,
    "principal_directory": _collect_principal_directory,
    "secure_score_controls": _collect_secure_score_controls,
    "mde_summary": _collect_mde_summary,
    "mde_health": _collect_mde_health,
    "intune_bundle": _collect_intune_bundle,
    "security_alerts_bundle": _collect_security_alerts,
    "sentinel_rules": _collect_sentinel_rules,
    "sentinel_ueba": _collect_sentinel_ueba,
    "sentinel_data_connectors": _collect_sentinel_data_connectors,
    "sentinel_automation_rules": _collect_sentinel_automation_rules,
    "sentinel_workspace": _collect_sentinel_workspace,
    "defender_for_cloud_pricings": _collect_defender_pricings,
    "purview_dlp": _collect_purview_dlp,
    "security_defaults_policy": _collect_security_defaults,
    "access_review_definitions": _collect_access_reviews,
    "auth_methods_bundle": _collect_auth_methods,
    "applications_bundle": _collect_applications,
    "authorization_policy": _collect_authorization_policy,
    "admin_consent_request_policy": _collect_admin_consent_policy,
    "guests_bundle": _collect_guests,
    "pim_policies_bundle": _collect_pim_policies,
    "domains": _collect_domains,
    "break_glass_principal_ids": _collect_break_glass,
    "approved_guest_domains": _collect_approved_guest_domains,
    "exchange_bundle": _collect_exchange,
    "dns_records": _collect_dns,
    "collaboration_bundle": _collect_collaboration,
    "power_data_bundle": _collect_power_data,
}


def build_runtime_collector_specs(
    ctx: ScanCollectionContext,
    registry: AssessmentRegistry,
) -> tuple[CollectorSpec, ...]:
    """Expand registered collector factories into unique live CollectorSpec closures."""
    produced: dict[str, CollectorSpec] = {}
    for entry in registry.collector_entries:
        factory = entry.factory
        if factory is None:
            continue
        for stub in factory():
            key = str(stub.produces)
            if key in produced:
                continue
            collect_fn = _COLLECTORS.get(key)
            if collect_fn is None:
                continue
            depends = _RUNTIME_DEPENDS.get(key)
            if depends is None:
                depends_on = tuple(dep for dep in stub.depends_on if str(dep) != key)
            else:
                depends_on = tuple(EvidenceKey(dep) for dep in depends)

            def _bound(
                context: CollectionContext,
                *,
                _fn: EvidenceCollectorFn = collect_fn,
                _ctx: ScanCollectionContext = ctx,
            ) -> EvidenceEnvelope:
                return _fn(_ctx, context)

            produced[key] = CollectorSpec(
                collector_id=CollectorId(str(stub.collector_id)),
                produces=EvidenceKey(key),
                collect=_bound,
                depends_on=depends_on,
                supported_clouds=stub.supported_clouds,
                timeout_seconds=stub.timeout_seconds,
            )

    # Ensure every known runtime key has a producer even if factory metadata drifts.
    for key, collect_fn in _COLLECTORS.items():
        if key in produced:
            continue
        depends = _RUNTIME_DEPENDS.get(key, ())

        def _bound_fallback(
            context: CollectionContext,
            *,
            _fn: EvidenceCollectorFn = collect_fn,
            _ctx: ScanCollectionContext = ctx,
        ) -> EvidenceEnvelope:
            return _fn(_ctx, context)

        produced[key] = CollectorSpec(
            collector_id=CollectorId(f"runtime:{key}"),
            produces=EvidenceKey(key),
            collect=_bound_fallback,
            depends_on=tuple(EvidenceKey(dep) for dep in depends),
            timeout_seconds=30,
        )

    return tuple(produced[key] for key in sorted(produced))


def check_requirements_for(
    check_ids: Sequence[str],
    registry: AssessmentRegistry,
    *,
    profile_ids: tuple[str, ...] = (),
) -> tuple[CheckEvidenceRequirement, ...]:
    requirements: list[CheckEvidenceRequirement] = []
    for check_id in check_ids:
        try:
            entry = registry.evaluator_for(check_id)
        except KeyError:
            continue
        requirements.append(
            CheckEvidenceRequirement(
                check_id=CheckId(check_id),
                evidence_keys=tuple(EvidenceKey(model) for model in entry.input_models),
                enabled=True,
                profile_ids=profile_ids,
            )
        )
    return tuple(requirements)


def collect_selected_evidence(
    ctx: ScanCollectionContext,
    registry: AssessmentRegistry,
    *,
    check_ids: Sequence[str],
    profile_ids: tuple[str, ...] = (),
) -> tuple[dict[str, Any], list[CollectionSummary], CollectionResult]:
    """Plan and collect evidence for the selected checks only."""
    specs = build_runtime_collector_specs(ctx, registry)
    requirements = check_requirements_for(check_ids, registry, profile_ids=profile_ids)
    planner = EvidencePlanner(collectors=specs)
    result = planner.collect(requirements, profile_ids=profile_ids)
    evidence = envelopes_to_evidence(result, ctx)
    summaries = collection_summaries_from(result)
    return evidence, summaries, result


def envelopes_to_evidence(
    result: CollectionResult,
    ctx: ScanCollectionContext,
) -> dict[str, Any]:
    """Convert planner envelopes into the evaluator-facing evidence dict."""
    evidence: dict[str, Any] = {
        "signin_lookback_days": 90,
        "signin_sample_truncated": False,
    }
    evidence.update(ctx.extras)

    for key, envelope in result.envelopes.items():
        name = str(key)
        if envelope.health in {EvidenceHealth.OK, EvidenceHealth.TRUNCATED}:
            value = envelope.value
            if name in _EXPAND_VALUE_KEYS and isinstance(value, dict):
                evidence.update(value)
            else:
                evidence[name] = value
            if envelope.health is EvidenceHealth.TRUNCATED and name == "recent_signin_user_ids":
                evidence["signin_sample_truncated"] = True
            continue

        err_key = _ERROR_ALIASES.get(name, f"{name}_error")
        if envelope.reason:
            evidence[err_key] = envelope.reason
        if name.startswith("sentinel") and not ctx.workspace_resource_id:
            evidence["sentinel_workspace_missing"] = True
        if name == "exchange_bundle":
            evidence.setdefault("exchange_threat_usable", False)
        if name == "secure_score_controls":
            evidence.setdefault("secure_score_controls", [])
        if name in {
            "role_assignments",
            "access_review_definitions",
            "domains",
        }:
            evidence.setdefault(name, [] if name != "role_assignments" else [])
        if name in {
            "security_defaults_policy",
            "auth_methods_bundle",
            "applications_bundle",
            "authorization_policy",
            "admin_consent_request_policy",
            "guests_bundle",
            "pim_policies_bundle",
            "principal_directory",
            "dns_records",
        }:
            if name == "dns_records":
                evidence.setdefault(name, {"domains": [], "records": {}})
            else:
                evidence.setdefault(name, {})

    bg = list(ctx.extras.get("break_glass_principal_ids") or [])
    evidence.setdefault("break_glass_principal_ids", bg)
    approved = list(ctx.extras.get("approved_guest_domains") or [])
    evidence.setdefault("approved_guest_domains", approved)
    return evidence


def collection_summaries_from(result: CollectionResult) -> list[CollectionSummary]:
    summaries: list[CollectionSummary] = []
    for key, envelope in sorted(result.envelopes.items(), key=lambda item: str(item[0])):
        status = envelope.collection_status
        warnings: list[str] = []
        errors: list[str] = []
        if status is CollectionStatus.FAILED and envelope.reason:
            errors.append(envelope.reason)
        elif envelope.reason and status is not CollectionStatus.SUCCESS:
            warnings.append(envelope.reason)
        summaries.append(
            CollectionSummary(
                collector=str(key),
                status=status,
                source=envelope.metadata.source,
                items_collected=envelope.metadata.items_collected,
                warnings=warnings,
                errors=errors,
            )
        )
    return summaries
