"""Sentinel and Defender for Cloud runtime collectors."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from licenselens.collectors.arm import subscription_id_from_resource_id
from licenselens.collectors.arm_selective import (
    DEMO_DEFENDER_PRICINGS,
    collect_defender_for_cloud_pricings,
    summarize_defender_for_cloud_pricings,
)
from licenselens.collectors.contracts import EvidenceEnvelope
from licenselens.collectors.runtime_envelopes import error, graph_failure, ok, unavailable
from licenselens.collectors.sentinel import DEMO_SENTINEL_RULES, DEMO_SENTINEL_UEBA
from licenselens.collectors.sentinel_extended import (
    DEMO_SENTINEL_AUTOMATION_RULES,
    DEMO_SENTINEL_DATA_CONNECTORS,
    DEMO_SENTINEL_WORKSPACE,
    collect_sentinel_extended_bundle,
)
from licenselens.engine.collection_context import ScanCollectionContext
from licenselens.engine.planner import CollectionContext
from licenselens.errors import AuthError, GraphError


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
    return unavailable("sentinel_rules", reason)


def collect_sentinel_rules_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "sentinel_rules"
    if ctx.is_dry_run:
        return ok(key, dict(DEMO_SENTINEL_RULES), source="demo")
    missing = _workspace_missing(ctx)
    if missing is not None:
        return unavailable(key, missing.reason)
    assert ctx.workspace_resource_id is not None
    try:
        import importlib

        bundle = importlib.import_module("licenselens.collectors.runtime").collect_sentinel_bundle(
            ctx.auth, ctx.workspace_resource_id
        )
        ctx.extras["workspace_resource_id"] = bundle.get("workspace_resource_id")
        if bundle.get("sentinel_ueba") is not None:
            ctx.extras["_sentinel_ueba_cache"] = bundle.get("sentinel_ueba") or {}
        return ok(key, bundle.get("sentinel_rules") or {}, source="arm.sentinel")
    except (AuthError, GraphError) as exc:
        return graph_failure(key, exc, f"Sentinel workspace could not be read: {exc}", ctx)


def collect_sentinel_ueba_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "sentinel_ueba"
    if ctx.is_dry_run:
        return ok(key, dict(DEMO_SENTINEL_UEBA), source="demo")
    if not ctx.workspace_resource_id:
        ctx.extras["sentinel_workspace_missing"] = True
        return unavailable(key, "No Sentinel workspace provided (--workspace-resource-id).")
    cached = ctx.extras.get("_sentinel_ueba_cache")
    if cached is not None:
        return ok(key, dict(cached), source="arm.sentinel")
    try:
        import importlib

        bundle = importlib.import_module("licenselens.collectors.runtime").collect_sentinel_bundle(
            ctx.auth, ctx.workspace_resource_id
        )
        return ok(key, bundle.get("sentinel_ueba") or {}, source="arm.sentinel")
    except (AuthError, GraphError) as exc:
        ctx.warn(f"Sentinel workspace could not be read: {exc}")
        return error(key, str(exc))


def _collect_sentinel_extended_key(
    ctx: ScanCollectionContext,
    _pc: CollectionContext,
    *,
    key: str,
    demo: Mapping[str, Any],
) -> EvidenceEnvelope:
    if ctx.is_dry_run:
        return ok(key, dict(demo), source="demo")
    if not ctx.workspace_resource_id:
        ctx.extras["sentinel_workspace_missing"] = True
        return unavailable(key, "No Sentinel workspace provided (--workspace-resource-id).")
    cache_key = "_sentinel_extended_cache"
    extended = ctx.extras.get(cache_key)
    if extended is None:
        try:
            extended = collect_sentinel_extended_bundle(ctx.auth, ctx.workspace_resource_id)
            ctx.extras[cache_key] = extended
        except (AuthError, GraphError) as exc:
            ctx.warn(f"Sentinel connectors/automation could not be read: {exc}")
            return error(key, str(exc))
    value = extended.get(key)
    err = extended.get(f"{key}_error")
    if err and value is None:
        return error(key, str(err))
    return ok(key, value if value is not None else {}, source="arm.sentinel")


def collect_sentinel_data_connectors_runtime(
    ctx: ScanCollectionContext, pc: CollectionContext
) -> EvidenceEnvelope:
    return _collect_sentinel_extended_key(
        ctx, pc, key="sentinel_data_connectors", demo=DEMO_SENTINEL_DATA_CONNECTORS
    )


def collect_sentinel_automation_rules_runtime(
    ctx: ScanCollectionContext, pc: CollectionContext
) -> EvidenceEnvelope:
    return _collect_sentinel_extended_key(
        ctx, pc, key="sentinel_automation_rules", demo=DEMO_SENTINEL_AUTOMATION_RULES
    )


def collect_sentinel_workspace_runtime(
    ctx: ScanCollectionContext, pc: CollectionContext
) -> EvidenceEnvelope:
    return _collect_sentinel_extended_key(
        ctx, pc, key="sentinel_workspace", demo=DEMO_SENTINEL_WORKSPACE
    )


def collect_defender_pricings_runtime(
    ctx: ScanCollectionContext, _pc: CollectionContext
) -> EvidenceEnvelope:
    key = "defender_for_cloud_pricings"
    if ctx.is_dry_run:
        return ok(key, dict(DEMO_DEFENDER_PRICINGS), source="demo")
    if not ctx.workspace_resource_id:
        reason = (
            "Selective-Azure checks require --workspace-resource-id "
            "(or subscription/resource-group/workspace-name)."
        )
        return error(key, reason)
    sub = subscription_id_from_resource_id(ctx.workspace_resource_id)
    if not sub:
        return error(
            key,
            "No Azure subscription could be derived from the workspace resource ID.",
        )
    try:
        from licenselens.collectors.arm import ArmClient

        with ArmClient(ctx.auth) as arm:
            pricings = collect_defender_for_cloud_pricings(arm, sub)
        summary = summarize_defender_for_cloud_pricings(pricings, sub)
        return ok(key, summary, source="arm.security.pricings")
    except (AuthError, GraphError) as exc:
        return graph_failure(
            key, exc, f"Defender for Cloud plan pricing could not be read: {exc}", ctx
        )
