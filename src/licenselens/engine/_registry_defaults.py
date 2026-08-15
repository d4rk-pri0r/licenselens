from __future__ import annotations

from functools import lru_cache

from licenselens.collectors.bindings import register_all_collectors
from licenselens.engine._registry_source_meta import SOURCE_META
from licenselens.engine.registration import RegistrationCatalog, merge_permissions
from licenselens.engine.registry import AssessmentRegistry, DataSourceEntry
from licenselens.evaluators.bindings import register_all_evaluators


@lru_cache(maxsize=1)
def build_default_registry() -> AssessmentRegistry:
    catalog = RegistrationCatalog()
    _register_data_sources(catalog)
    register_all_collectors(catalog)
    register_all_evaluators(catalog)
    _apply_merged_permissions(catalog)
    return catalog.build()


def _register_data_sources(catalog: RegistrationCatalog) -> None:
    for source_id, meta in sorted(SOURCE_META.items()):
        catalog.add_data_source(
            DataSourceEntry(
                id=source_id,
                output_model=_source_model(source_id),
                backend=meta[0],
                permissions=meta[1],
                cloud_support=("public",),
                cache_key=meta[2],
                timeout_seconds=meta[3],
            )
        )


def _apply_merged_permissions(catalog: RegistrationCatalog) -> None:
    """Fill evaluator permissions from bound input models after all registrations."""
    from licenselens.engine.registry import EvaluatorEntry

    for check_id, entry in list(catalog.evaluators.items()):
        permissions = merge_permissions(entry.input_models, SOURCE_META)
        if entry.permissions == permissions:
            continue
        catalog.evaluators[check_id] = EvaluatorEntry(
            id=entry.id,
            evaluator=entry.evaluator,
            evaluate=entry.evaluate,
            input_models=entry.input_models,
            output_model=entry.output_model,
            backend=entry.backend,
            permissions=permissions,
            cloud_support=entry.cloud_support,
            cache_key=entry.cache_key,
            timeout_seconds=entry.timeout_seconds,
            dependencies=entry.dependencies,
            evaluation_mode=entry.evaluation_mode,
        )


def _source_model(source_id: str) -> str:
    if source_id == "recent_signin_user_ids":
        return "set[str]"
    if source_id in {"break_glass_principal_ids", "approved_guest_domains"}:
        return "tuple[str, ...]"
    if source_id in {
        "purview_dlp",
        "sentinel_rules",
        "sentinel_ueba",
        "sentinel_data_connectors",
        "sentinel_automation_rules",
        "sentinel_workspace",
        "defender_for_cloud_pricings",
        "auth_methods_bundle",
        "applications_bundle",
        "guests_bundle",
        "pim_policies_bundle",
        "admin_consent_request_policy",
        "exchange_bundle",
        "dns_records",
        "collaboration_bundle",
        "power_data_bundle",
        "intune_bundle",
        "mde_health",
        "security_alerts_bundle",
    }:
        return "JsonObject"
    if source_id.endswith("_policy") or source_id.endswith("_summary"):
        return "JsonObject"
    return "tuple[JsonObject, ...]"
