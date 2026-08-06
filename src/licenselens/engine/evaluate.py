"""Check evaluators — pure functions over collected evidence."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from licenselens.collectors import conditional_access as ca
from licenselens.models import CheckDefinition, FindingStatus


@dataclass
class Evaluation:
    status: FindingStatus
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    # Optional overrides for customer-facing copy when status is nuanced
    customer_summary: str | None = None


Evaluator = Callable[[CheckDefinition, dict[str, Any]], Evaluation]


def evaluate_ca_priv_gaps(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess MFA coverage and legacy-auth blocking via Conditional Access."""
    del check  # metadata unused; signature shared with registry
    policies: list[dict[str, Any]] = list(evidence.get("ca_policies") or [])
    enabled = [p for p in policies if ca.is_enabled(p)]
    report_only = [p for p in policies if ca.is_report_only(p)]

    mfa_enforced = [
        p
        for p in enabled
        if ca.requires_mfa(p) and (ca.includes_all_users(p) or ca.targets_privileged_roles(p))
    ]
    mfa_report = [
        p
        for p in report_only
        if ca.requires_mfa(p) and (ca.includes_all_users(p) or ca.targets_privileged_roles(p))
    ]
    legacy_enforced = [p for p in enabled if ca.is_legacy_auth_block(p)]
    legacy_report = [p for p in report_only if ca.is_legacy_auth_block(p)]

    evidence_out = {
        "policy_count": len(policies),
        "enabled_count": len(enabled),
        "report_only_count": len(report_only),
        "mfa_enforced_policies": [p.get("displayName") for p in mfa_enforced],
        "mfa_report_only_policies": [p.get("displayName") for p in mfa_report],
        "legacy_block_enforced": [p.get("displayName") for p in legacy_enforced],
        "legacy_block_report_only": [p.get("displayName") for p in legacy_report],
    }

    if not policies:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No Conditional Access policies were found.",
            evidence=evidence_out,
            customer_summary=(
                "We did not find sign-in rules that require extra verification. "
                "Powerful accounts may be able to sign in with only a password."
            ),
        )

    has_mfa = bool(mfa_enforced)
    has_legacy = bool(legacy_enforced)
    has_mfa_ro = bool(mfa_report)
    has_legacy_ro = bool(legacy_report)

    if has_mfa and has_legacy:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                "Enforced Conditional Access requires MFA for users/admins and "
                "blocks legacy authentication clients."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Strong sign-in rules look enforced: extra verification is required "
                "and outdated sign-in methods are blocked."
            ),
        )

    if has_mfa or has_legacy or has_mfa_ro or has_legacy_ro:
        missing: list[str] = []
        if not has_mfa:
            missing.append(
                "enforced MFA for all users or privileged roles"
                + (" (report-only MFA exists)" if has_mfa_ro else "")
            )
        if not has_legacy:
            missing.append(
                "enforced legacy authentication block"
                + (" (report-only legacy block exists)" if has_legacy_ro else "")
            )
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Conditional Access is partially configured: missing "
            + "; ".join(missing)
            + ".",
            evidence=evidence_out,
            customer_summary=(
                "Some sign-in protections are present, but the full set is not "
                "enforced yet (multi-factor authentication and/or blocking outdated "
                "sign-in methods)."
            ),
        )

    return Evaluation(
        status=FindingStatus.GAP,
        summary=(
            f"Found {len(policies)} Conditional Access policy(ies), but none "
            "clearly enforce MFA for users/admins or block legacy authentication."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Sign-in rules may exist, but they do not clearly require strong "
            "verification for important accounts or block outdated sign-in methods."
        ),
    )


def evaluate_idprotect_off(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess risk-based Conditional Access (Identity Protection outcomes)."""
    del check
    policies: list[dict[str, Any]] = list(evidence.get("ca_policies") or [])
    risk_policies = [p for p in policies if ca.has_risk_conditions(p)]

    def _enforced_risk(kind: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for p in risk_policies:
            if not ca.is_enabled(p):
                continue
            levels = (
                ca.sign_in_risk_levels(p) if kind == "sign_in" else ca.user_risk_levels(p)
            )
            if not levels:
                continue
            controls = {
                str(c).lower()
                for c in ((p.get("grantControls") or {}).get("builtInControls") or [])
            }
            if ca.requires_mfa(p) or ca.is_block_policy(p) or "passwordchange" in controls:
                out.append(p)
        return out

    def _report_risk(kind: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for p in risk_policies:
            if not ca.is_report_only(p):
                continue
            levels = (
                ca.sign_in_risk_levels(p) if kind == "sign_in" else ca.user_risk_levels(p)
            )
            if levels:
                out.append(p)
        return out

    sign_in_enforced = _enforced_risk("sign_in")
    user_enforced = _enforced_risk("user")
    sign_in_report = _report_risk("sign_in")
    user_report = _report_risk("user")

    evidence_out = {
        "risk_policy_count": len(risk_policies),
        "sign_in_risk_enforced": [p.get("displayName") for p in sign_in_enforced],
        "user_risk_enforced": [p.get("displayName") for p in user_enforced],
        "sign_in_risk_report_only": [p.get("displayName") for p in sign_in_report],
        "user_risk_report_only": [p.get("displayName") for p in user_report],
    }

    if sign_in_enforced and user_enforced:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                "Enforced Conditional Access policies address both sign-in risk "
                "and user risk (Identity Protection outcomes)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Suspicious sign-ins and risky accounts appear to trigger automatic "
                "extra checks or blocks."
            ),
        )

    if sign_in_enforced or user_enforced or sign_in_report or user_report:
        bits: list[str] = []
        if not sign_in_enforced:
            bits.append(
                "enforced sign-in risk policy"
                + (" (report-only present)" if sign_in_report else " missing")
            )
        if not user_enforced:
            bits.append(
                "enforced user risk policy"
                + (" (report-only present)" if user_report else " missing")
            )
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Identity Protection–style risk controls are incomplete: "
            + "; ".join(bits)
            + ".",
            evidence=evidence_out,
            customer_summary=(
                "Some suspicious-sign-in protections exist, but they are incomplete "
                "or still in report-only mode — risky logins may not be stopped."
            ),
        )

    return Evaluation(
        status=FindingStatus.GAP,
        summary=(
            "No Conditional Access policies with user-risk or sign-in-risk "
            "conditions were found (Identity Protection not operationalized via CA)."
        ),
        evidence=evidence_out,
        customer_summary=(
            "We did not find automatic responses when Microsoft marks a sign-in "
            "or account as risky. That protection may still be turned off."
        ),
    )


EVALUATORS: dict[str, Evaluator] = {
    "id-ca-priv-gaps": evaluate_ca_priv_gaps,
    "id-idprotect-off": evaluate_idprotect_off,
}
