"""Envelope helpers and planner-result conversion for runtime collectors."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from licenselens.collectors.contracts import (
    CollectionMetadata,
    EvidenceEnvelope,
    EvidenceHealth,
    EvidenceKey,
    PaginationMetadata,
)
from licenselens.engine.collection_context import ScanCollectionContext
from licenselens.engine.planner import CollectionContext, CollectionResult
from licenselens.schema_contracts import CollectionStatus, CollectionSummary

type EvidenceCollectorFn = Callable[
    [ScanCollectionContext, CollectionContext],
    EvidenceEnvelope,
]

# Keys whose envelope value is a multi-field dict that must be merged into evidence.
EXPAND_VALUE_KEYS = frozenset(
    {
        "exchange_bundle",
        "collaboration_bundle",
        "power_data_bundle",
    }
)

ERROR_ALIASES: dict[str, str] = {
    "ca_policies": "ca_policies_error",
    "security_defaults_policy": "security_defaults_policy_error",
    "access_review_definitions": "access_review_definitions_error",
    "access_review_instances": "access_review_instances_error",
    "access_packages": "access_packages_error",
    "risky_service_principals": "risky_service_principals_error",
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


def meta(source: str, items: int = 0, *, truncated: bool = False) -> CollectionMetadata:
    return CollectionMetadata(
        source=source,
        items_collected=items,
        pagination=PaginationMetadata(
            pages_read=1 if items else 0,
            max_pages=1,
            next_link_seen=False,
        ),
    )


def ok(
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
            metadata=meta(source, items, truncated=True),
        )
    return EvidenceEnvelope(
        key=ek,
        health=EvidenceHealth.OK,
        value=value,
        metadata=meta(source, items),
    )


def denied(key: str, reason: str) -> EvidenceEnvelope:
    return EvidenceEnvelope.denied(EvidenceKey(key), reason=reason)


def error(key: str, reason: str) -> EvidenceEnvelope:
    return EvidenceEnvelope.error(EvidenceKey(key), reason=reason)


def unavailable(key: str, reason: str) -> EvidenceEnvelope:
    return EvidenceEnvelope.unavailable(EvidenceKey(key), reason=reason)


def is_denied(exc: BaseException) -> bool:
    text = str(exc)
    return "403" in text or "Authorization_RequestDenied" in text or "AccessDenied" in text


def graph_failure(
    key: str,
    exc: BaseException,
    warn: str,
    ctx: ScanCollectionContext,
) -> EvidenceEnvelope:
    ctx.warn(warn)
    reason = str(exc)
    if is_denied(exc):
        return denied(key, reason)
    return error(key, reason)


def envelope_value(context: CollectionContext, key: str) -> Any:
    env = context.envelopes.get(EvidenceKey(key))
    if env is None or not env.is_usable:
        return None
    return env.value


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
            if name in EXPAND_VALUE_KEYS and isinstance(value, dict):
                evidence.update(value)
            else:
                evidence[name] = value
            if envelope.health is EvidenceHealth.TRUNCATED and name == "recent_signin_user_ids":
                evidence["signin_sample_truncated"] = True
            continue

        err_key = ERROR_ALIASES.get(name, f"{name}_error")
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
            "access_review_instances",
            "risky_service_principals",
            "domains",
        }:
            evidence.setdefault(name, [])
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
