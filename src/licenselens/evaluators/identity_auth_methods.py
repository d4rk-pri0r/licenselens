"""Authentication methods policy evaluators."""

from __future__ import annotations

from typing import Any, Final

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, FindingStatus

_WEAK_METHOD_IDS: Final = frozenset({"sms", "voice", "email", "emailotp"})


def _configurations(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    bundle = evidence.get("auth_methods_bundle") or {}
    if isinstance(bundle, dict) and bundle.get("configurations") is not None:
        return list(bundle.get("configurations") or [])
    return list(evidence.get("auth_method_configurations") or [])


def _policy(evidence: dict[str, Any]) -> dict[str, Any]:
    bundle = evidence.get("auth_methods_bundle") or {}
    if isinstance(bundle, dict) and bundle.get("policy") is not None:
        policy = bundle.get("policy") or {}
        return policy if isinstance(policy, dict) else {}
    policy = evidence.get("auth_methods_policy") or {}
    return policy if isinstance(policy, dict) else {}


def evaluate_auth_methods_migration(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    policy = _policy(evidence)
    state = str(policy.get("policyMigrationState") or "").lower()
    evidence_out = {"policy_migration_state": state or None}
    if state in {"migrationcomplete", "complete"}:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Authentication methods migration is complete.",
            evidence=evidence_out,
            customer_summary=("Sign-in methods are managed from the modern central policy page."),
        )
    if state in {"migrationinprogress", "inprogress"}:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=f"Authentication methods migration is still in progress ({state}).",
            evidence=evidence_out,
            customer_summary=(
                "Your organization started consolidating sign-in methods but has not finished."
            ),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary=(f"Authentication methods migration is not complete (state={state or 'unknown'})."),
        evidence=evidence_out,
        customer_summary=(
            "Legacy and modern sign-in method screens may both still be active, "
            "which makes misconfiguration more likely."
        ),
    )


def evaluate_auth_weak_methods_disabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    configs = _configurations(evidence)
    enabled_weak: list[str] = []
    for item in configs:
        method_id = str(item.get("id") or "").lower()
        state = str(item.get("state") or "").lower()
        if method_id in _WEAK_METHOD_IDS and state == "enabled":
            enabled_weak.append(method_id)
    evidence_out = {
        "enabled_weak_methods": sorted(set(enabled_weak)),
        "configuration_count": len(configs),
    }
    if not configs:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Authentication method configurations were not available.",
            evidence=evidence_out,
            customer_summary=("We could not read which weak sign-in methods are still allowed."),
        )
    if enabled_weak:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "Weak authentication methods remain enabled: "
                + ", ".join(sorted(set(enabled_weak)))
                + "."
            ),
            evidence=evidence_out,
            customer_summary=(
                "SMS, voice, or email one-time codes are still allowed — these are "
                "the easiest multi-factor methods for attackers to abuse."
            ),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="SMS, voice, and email OTP authentication methods are disabled.",
        evidence=evidence_out,
        customer_summary="The weakest multi-factor methods are turned off.",
    )


def evaluate_auth_authenticator_context(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    configs = _configurations(evidence)
    authenticator = next(
        (c for c in configs if str(c.get("id") or "").lower() == "microsoftauthenticator"),
        None,
    )
    if authenticator is None:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Microsoft Authenticator configuration was not found.",
            evidence={"authenticator_present": False},
            customer_summary=("We could not confirm whether Authenticator shows login context."),
        )
    state = str(authenticator.get("state") or "").lower()
    feature = authenticator.get("featureSettings") or {}
    if not isinstance(feature, dict):
        feature = {}
    app_name = feature.get("displayAppInformationRequiredState") or {}
    geo = feature.get("displayLocationInformationRequiredState") or {}
    app_on = str((app_name or {}).get("state") or "").lower() == "enabled"
    geo_on = str((geo or {}).get("state") or "").lower() == "enabled"
    number_setting = feature.get("numberMatchingRequiredState")
    has_number_setting = isinstance(number_setting, dict)
    number_on = str((number_setting or {}).get("state") or "").lower() == "enabled"
    evidence_out = {
        "authenticator_state": state,
        "show_app_name": app_on,
        "show_location": geo_on,
        "number_matching_enabled": number_on if has_number_setting else None,
    }
    if state != "enabled":
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "Microsoft Authenticator is not enabled tenant-wide, so sign-in "
                "context protection is absent."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Authenticator is not active, so users are not protected by "
                "number-matching push notifications that show app and location context."
            ),
        )
    if app_on and geo_on and (number_on or not has_number_setting):
        return Evaluation(
            status=FindingStatus.OK,
            summary=("Microsoft Authenticator shows application name and geographic location."),
            evidence=evidence_out,
            customer_summary=(
                "Authenticator prompts show which app and where the sign-in is from."
            ),
        )
    if not number_on and has_number_setting:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "Microsoft Authenticator is enabled but number matching is disabled."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Without number matching, users can approve a sign-in without "
                "typing the code shown on screen, which makes push phishing easier."
            ),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary=(
            "Microsoft Authenticator is enabled without full login context "
            f"(app_name={app_on}, location={geo_on})."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Authenticator prompts do not clearly show app and location context, "
            "which makes push phishing harder to spot."
        ),
    )
