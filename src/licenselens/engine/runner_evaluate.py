"""Per-check evaluation orchestration for scan runs."""

from __future__ import annotations

from typing import Any

from licenselens.engine.registry import AssessmentRegistry
from licenselens.engine.runner_findings import (
    base_finding,
    eligible,
    error_finding,
    from_evaluation,
    not_licensed_finding,
    skipped_finding,
)
from licenselens.models import CheckDefinition, Confidence, Finding, FindingStatus

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

_OPTIONAL_MISSING = {
    "break_glass_principal_ids",
    "approved_guest_domains",
    "role_eligibilities",
}

_ERROR_ALIASES = {
    "ca_policies": "ca_policies_error",
    "security_defaults_policy": "security_defaults_policy_error",
    "access_review_definitions": "access_review_definitions_error",
    "access_packages": "access_packages_error",
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


def evaluate_check(
    check: CheckDefinition,
    owned: set[str],
    evidence: dict[str, Any],
    *,
    strict_proxy: bool = True,
    allow_email_proxy: bool = False,
    registry: AssessmentRegistry | None = None,
) -> Finding:
    if not eligible(check, owned):
        return not_licensed_finding(check, owned, strict_proxy=strict_proxy)

    if registry is None:
        import importlib

        assessment = importlib.import_module("licenselens.engine.runner").default_registry()
    else:
        assessment = registry
    try:
        entry = assessment.evaluator_for(check.id)
    except KeyError:
        return skipped_finding(check, owned, strict_proxy=strict_proxy)
    evaluator = entry.evaluate
    if evaluator is None:
        return skipped_finding(check, owned, strict_proxy=strict_proxy)

    # MDO: prefer direct Exchange PowerShell; Secure Score proxy is opt-in fallback only.
    if check.id == "mdo-p2-policies-default":
        if evidence.get("exchange_threat_usable"):
            pass  # evaluate via direct EXO evidence below
        elif not allow_email_proxy:
            return base_finding(
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
    for key in required_keys:
        err_key = _ERROR_ALIASES.get(key, f"{key}_error")
        if key == "secure_score_controls" and evidence.get("secure_score_controls_error"):
            if check.id == "mdo-p2-policies-default" and evidence.get("exchange_threat_usable"):
                continue
            return error_finding(
                check,
                owned,
                str(evidence["secure_score_controls_error"]),
                strict_proxy=strict_proxy,
            )
        if key == "sentinel_ueba" and evidence.get("sentinel_ueba_error"):
            if "sentinel_ueba" not in evidence:
                return error_finding(
                    check,
                    owned,
                    str(evidence["sentinel_ueba_error"]),
                    strict_proxy=strict_proxy,
                )
            continue
        if evidence.get(err_key) and key not in _OPTIONAL_MISSING:
            return error_finding(check, owned, str(evidence[err_key]), strict_proxy=strict_proxy)
        if key not in evidence and err_key not in evidence:
            if key in _OPTIONAL_MISSING:
                continue
            if key in {
                "sentinel_rules",
                "sentinel_ueba",
                "sentinel_data_connectors",
                "sentinel_automation_rules",
                "sentinel_workspace",
            } and evidence.get("sentinel_workspace_missing"):
                continue
            return error_finding(
                check,
                owned,
                f"Required evidence '{key}' was not collected.",
                strict_proxy=strict_proxy,
            )

    try:
        result = evaluator(check, evidence)
    except Exception as exc:  # noqa: BLE001
        return error_finding(check, owned, str(exc), strict_proxy=strict_proxy)
    return from_evaluation(check, owned, result, strict_proxy=strict_proxy)
