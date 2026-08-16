"""Endpoint and Secure Score runtime collectors (MDE, Intune, alerts, Purview)."""

from __future__ import annotations

from licenselens.collectors.contracts import EvidenceEnvelope, EvidenceKey
from licenselens.collectors.intune_policy import (
    DEMO_INTUNE_EVIDENCE_BUNDLE,
    collect_intune_evidence_bundle,
    intune_licensed_units,
)
from licenselens.collectors.mde import DEMO_MDE_SUMMARY, mde_licensed_units
from licenselens.collectors.mde_health import DEMO_MDE_HEALTH, collect_mde_health_summary
from licenselens.collectors.pbi_admin import DEMO_PBI_CAPACITY_BUNDLE, collect_pbi_capacity_bundle
from licenselens.collectors.purview import (
    DEMO_DLP_BUNDLE,
    DEMO_EDISCOVERY_BUNDLE,
    DEMO_INSIDER_RISK_BUNDLE,
    collect_purview_dlp_bundle,
    collect_purview_ediscovery_bundle,
    collect_purview_insider_risk_bundle,
)
from licenselens.collectors.runtime_envelopes import (
    envelope_value,
    error,
    graph_failure,
    ok,
)
from licenselens.collectors.secure_score import (
    DEMO_SECURE_SCORE,
    collect_latest_secure_score,
    extract_control_scores,
)
from licenselens.collectors.security_alerts import (
    DEMO_SECURITY_ALERTS_BUNDLE,
    collect_security_alerts_bundle,
)
from licenselens.engine.collection_context import ScanCollectionContext
from licenselens.engine.planner import CollectionContext
from licenselens.errors import AuthError, GraphError
from licenselens.graph import GraphClient


def collect_secure_score_controls_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "secure_score_controls"
    if ctx.is_dry_run:
        controls = extract_control_scores(DEMO_SECURE_SCORE)
        return ok(key, controls, source="demo", items=len(controls))
    assert ctx.client is not None
    try:
        score = collect_latest_secure_score(ctx.client)
        controls = extract_control_scores(score)
        ctx.extras["secure_score"] = score
        return ok(key, controls, source="graph.security.secureScores", items=len(controls))
    except GraphError as exc:
        return graph_failure(key, exc, f"Secure Score could not be read: {exc}", ctx)


def collect_mde_summary_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "mde_summary"
    licensed = mde_licensed_units(ctx.skus)
    if ctx.is_dry_run:
        summary = dict(DEMO_MDE_SUMMARY)
        summary["licensed_units"] = licensed
        return ok(key, summary, source="demo", items=int(summary.get("sample_size") or 0))
    try:
        import importlib

        mde = importlib.import_module("licenselens.collectors.runtime").collect_mde_machine_summary(
            ctx.auth
        )
        mde["licensed_units"] = licensed
        return ok(key, mde, source="mde.machines", items=int(mde.get("sample_size") or 0))
    except (AuthError, GraphError) as exc:
        return graph_failure(
            key, exc, f"Defender for Endpoint inventory could not be read: {exc}", ctx
        )


def collect_mde_health_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "mde_health"
    if ctx.is_dry_run:
        return ok(key, dict(DEMO_MDE_HEALTH), source="demo")
    try:
        health = collect_mde_health_summary(ctx.auth)
        return ok(key, health, source="mde.machineHealth")
    except (AuthError, GraphError) as exc:
        return graph_failure(
            key, exc, f"Defender for Endpoint sensor health could not be read: {exc}", ctx
        )


def collect_intune_bundle_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "intune_bundle"
    if ctx.is_dry_run:
        return ok(key, dict(DEMO_INTUNE_EVIDENCE_BUNDLE), source="demo")
    assert ctx.client is not None
    try:
        bundle = collect_intune_evidence_bundle(
            ctx.client, licensed_units=intune_licensed_units(ctx.skus)
        )
        return ok(key, bundle, source="graph.deviceManagement")
    except (AuthError, GraphError) as exc:
        return graph_failure(
            key, exc, f"Intune device management state could not be read: {exc}", ctx
        )


def collect_security_alerts_runtime(
    ctx: ScanCollectionContext,
    _pc: CollectionContext,
) -> EvidenceEnvelope:
    key = "security_alerts_bundle"
    if ctx.is_dry_run:
        return ok(key, dict(DEMO_SECURITY_ALERTS_BUNDLE), source="demo")
    assert ctx.client is not None
    try:
        bundle = collect_security_alerts_bundle(ctx.client)
        return ok(key, bundle, source="graph.security")
    except GraphError as exc:
        return graph_failure(key, exc, f"Security incidents/alerts could not be read: {exc}", ctx)


def collect_purview_dlp_runtime(
    ctx: ScanCollectionContext, pc: CollectionContext
) -> EvidenceEnvelope:
    key = "purview_dlp"
    if ctx.is_dry_run:
        return ok(key, dict(DEMO_DLP_BUNDLE), source="demo")
    controls = list(envelope_value(pc, "secure_score_controls") or [])
    score_env = pc.envelopes.get(EvidenceKey("secure_score_controls"))
    if score_env is not None and not score_env.is_usable and not controls:
        ctx.warn("Secure Score controls unavailable; direct Graph DLP read will be attempted.")
    assert ctx.client is not None
    try:
        bundle = collect_purview_dlp_bundle(ctx.client, controls)
        if bundle.get("proxy"):
            return ok(key, bundle, source="secureScore.controlScores (proxy)")
        return ok(key, bundle, source="graph.security.dataLossPreventionPolicies")
    except GraphError as exc:
        return graph_failure(key, exc, f"Purview DLP evidence could not be read: {exc}", ctx)


def collect_purview_ediscovery_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "purview_ediscovery"
    if ctx.is_dry_run:
        return ok(key, dict(DEMO_EDISCOVERY_BUNDLE), source="demo")
    assert ctx.client is not None
    try:
        bundle = collect_purview_ediscovery_bundle(ctx.client)
        return ok(key, bundle, source="graph.security.cases.ediscoveryCases")
    except GraphError as exc:
        return graph_failure(key, exc, f"Purview eDiscovery cases could not be read: {exc}", ctx)


def collect_purview_insider_risk_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "purview_insider_risk"
    if ctx.is_dry_run:
        return ok(key, dict(DEMO_INSIDER_RISK_BUNDLE), source="demo")
    if ctx.client is None:
        return error(key, "no Graph client available")
    try:
        preview = _preview_client(ctx, ctx.client)
        bundle = collect_purview_insider_risk_bundle(preview)
        return ok(key, bundle, source="graph.beta.security.insiderRiskManagement.policies")
    except GraphError as exc:
        return graph_failure(
            key,
            exc,
            f"Purview Insider Risk Management policies could not be read: {exc}",
            ctx,
        )


def _preview_client(ctx: ScanCollectionContext, base_client: GraphClient) -> GraphClient:
    """Build a preview-enabled Graph client (beta endpoints are otherwise blocked)."""
    return GraphClient(ctx.auth, cloud=base_client.cloud, allow_preview=True)


def collect_pbi_capacity_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "pbi_capacity_bundle"
    if ctx.is_dry_run:
        return ok(key, dict(DEMO_PBI_CAPACITY_BUNDLE), source="demo")
    try:
        bundle = collect_pbi_capacity_bundle(ctx.auth)
        return ok(key, bundle, source="powerbi.admin.rest")
    except (AuthError, GraphError) as exc:
        return graph_failure(key, exc, f"Power BI admin REST could not be read: {exc}", ctx)
