"""Build runtime CollectorSpec closures and run selected-check collection."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from licenselens.collectors.contracts import CheckId, CollectorId, EvidenceEnvelope, EvidenceKey
from licenselens.collectors.runtime_collect_identity_apps import (
    collect_admin_consent_policy_runtime,
    collect_applications_runtime,
    collect_approved_guest_domains_runtime,
    collect_auth_methods_runtime,
    collect_authorization_policy_runtime,
    collect_break_glass_runtime,
    collect_domains_runtime,
    collect_guests_runtime,
    collect_pim_policies_runtime,
)
from licenselens.collectors.runtime_collect_identity_core import (
    collect_access_reviews_runtime,
    collect_ca_policies_runtime,
    collect_principal_directory_runtime,
    collect_recent_signins_runtime,
    collect_role_assignments_runtime,
    collect_role_eligibilities_runtime,
    collect_security_defaults_runtime,
)
from licenselens.collectors.runtime_collect_mail import (
    collect_collaboration_runtime,
    collect_dns_runtime,
    collect_exchange_runtime,
    collect_power_data_runtime,
)
from licenselens.collectors.runtime_collect_endpoint import (
    collect_intune_bundle_runtime,
    collect_mde_health_runtime,
    collect_mde_summary_runtime,
    collect_purview_dlp_runtime,
    collect_secure_score_controls_runtime,
    collect_security_alerts_runtime,
)
from licenselens.collectors.runtime_collect_sentinel import (
    collect_defender_pricings_runtime,
    collect_sentinel_automation_rules_runtime,
    collect_sentinel_data_connectors_runtime,
    collect_sentinel_rules_runtime,
    collect_sentinel_ueba_runtime,
    collect_sentinel_workspace_runtime,
)
from licenselens.collectors.runtime_envelopes import (
    EvidenceCollectorFn,
    collection_summaries_from,
    envelopes_to_evidence,
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
from licenselens.schema_contracts import CollectionSummary

# Canonical dependency edges for the runtime DAG (overrides factory chain order).
_RUNTIME_DEPENDS: dict[str, tuple[str, ...]] = {
    "principal_directory": ("role_assignments",),
    "purview_dlp": ("secure_score_controls",),
    "dns_records": ("domains",),
    "admin_consent_request_policy": (),
    "approved_guest_domains": (),
    "break_glass_principal_ids": (),
}

_COLLECTORS: dict[str, EvidenceCollectorFn] = {
    "ca_policies": collect_ca_policies_runtime,
    "role_assignments": collect_role_assignments_runtime,
    "role_eligibilities": collect_role_eligibilities_runtime,
    "recent_signin_user_ids": collect_recent_signins_runtime,
    "principal_directory": collect_principal_directory_runtime,
    "secure_score_controls": collect_secure_score_controls_runtime,
    "mde_summary": collect_mde_summary_runtime,
    "mde_health": collect_mde_health_runtime,
    "intune_bundle": collect_intune_bundle_runtime,
    "security_alerts_bundle": collect_security_alerts_runtime,
    "sentinel_rules": collect_sentinel_rules_runtime,
    "sentinel_ueba": collect_sentinel_ueba_runtime,
    "sentinel_data_connectors": collect_sentinel_data_connectors_runtime,
    "sentinel_automation_rules": collect_sentinel_automation_rules_runtime,
    "sentinel_workspace": collect_sentinel_workspace_runtime,
    "defender_for_cloud_pricings": collect_defender_pricings_runtime,
    "purview_dlp": collect_purview_dlp_runtime,
    "security_defaults_policy": collect_security_defaults_runtime,
    "access_review_definitions": collect_access_reviews_runtime,
    "auth_methods_bundle": collect_auth_methods_runtime,
    "applications_bundle": collect_applications_runtime,
    "authorization_policy": collect_authorization_policy_runtime,
    "admin_consent_request_policy": collect_admin_consent_policy_runtime,
    "guests_bundle": collect_guests_runtime,
    "pim_policies_bundle": collect_pim_policies_runtime,
    "domains": collect_domains_runtime,
    "break_glass_principal_ids": collect_break_glass_runtime,
    "approved_guest_domains": collect_approved_guest_domains_runtime,
    "exchange_bundle": collect_exchange_runtime,
    "dns_records": collect_dns_runtime,
    "collaboration_bundle": collect_collaboration_runtime,
    "power_data_bundle": collect_power_data_runtime,
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
