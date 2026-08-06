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


def evaluate_pim_unused(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess whether privileged access uses PIM eligibility vs standing roles."""
    del check
    from licenselens.collectors import privileged_roles as priv

    assignments = list(evidence.get("role_assignments") or [])
    eligibilities = list(evidence.get("role_eligibilities") or [])

    priv_asg = priv.filter_privileged_assignments(assignments)
    priv_elig = priv.filter_privileged_eligibilities(eligibilities)

    permanent_principals = {
        str(a.get("principalId")) for a in priv_asg if a.get("principalId")
    }
    eligible_principals = {
        str(s.get("principalId")) for s in priv_elig if s.get("principalId")
    }
    ga_standing = [
        a
        for a in priv_asg
        if str(a.get("roleDefinitionId") or "").lower()
        == priv.GLOBAL_ADMIN_TEMPLATE_ID.lower()
    ]

    evidence_out = {
        "privileged_permanent_assignments": len(priv_asg),
        "privileged_eligible_schedules": len(priv_elig),
        "privileged_permanent_principals": len(permanent_principals),
        "privileged_eligible_principals": len(eligible_principals),
        "global_admin_standing_assignments": len(ga_standing),
        "sample_standing_roles": sorted(
            {
                priv.ROLE_DISPLAY_NAMES.get(
                    str(a.get("roleDefinitionId")),
                    str(a.get("roleDefinitionId")),
                )
                for a in priv_asg[:20]
            }
        ),
    }

    if not priv_asg and not priv_elig:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "No privileged directory role assignments or PIM eligibilities "
                "were found in the scanned role set."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could not find high-privilege admin assignments in the usual "
                "role list. Confirm directory permissions, or you may use a "
                "different admin model."
            ),
        )

    if priv_asg and not priv_elig:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"Found {len(priv_asg)} standing privileged role assignment(s) and "
                "0 PIM eligible schedules — just-in-time admin access is not in use."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Admin superpowers appear permanently on. Time-limited admin access "
                "(included in your stronger identity plan) does not look like it is "
                "being used."
            ),
        )

    if ga_standing and len(ga_standing) >= 2 and len(priv_elig) < len(priv_asg):
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"PIM eligibilities exist ({len(priv_elig)}), but "
                f"{len(priv_asg)} standing privileged assignments remain "
                f"(including {len(ga_standing)} Global Administrator)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Some just-in-time admin access is configured, but several powerful "
                "accounts still have permanent admin rights."
            ),
        )

    if len(priv_elig) >= len(priv_asg) and len(ga_standing) <= 1:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                "Privileged access appears PIM-oriented: eligible schedules are "
                "present and standing privileged assignments are limited."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Admin access looks closer to 'only when needed' rather than "
                "always-on superpowers for many people."
            ),
        )

    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=(
            f"Mixed privileged access model: {len(priv_asg)} standing assignment(s), "
            f"{len(priv_elig)} PIM eligible schedule(s)."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Your organization has started using time-limited admin access, but "
            "permanent high-power roles are still common."
        ),
    )


def evaluate_dormant_privileged(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Find enabled privileged principals with no successful sign-in in lookback."""
    del check
    from licenselens.collectors import privileged_roles as priv

    assignments = list(evidence.get("role_assignments") or [])
    recent_signins: set[str] = set(evidence.get("recent_signin_user_ids") or [])
    directory: dict[str, Any] = dict(evidence.get("principal_directory") or {})
    lookback_days = int(evidence.get("signin_lookback_days") or 90)
    signin_truncated = bool(evidence.get("signin_sample_truncated"))

    priv_asg = priv.filter_privileged_assignments(assignments)
    principal_ids = sorted(
        {str(a.get("principalId")) for a in priv_asg if a.get("principalId")}
    )

    dormant_users: list[dict[str, str]] = []
    active_users = 0
    disabled_or_unknown = 0
    non_user_principals = 0

    for pid in principal_ids:
        obj = directory.get(pid) or {}
        odata = str(obj.get("@odata.type") or "")
        # Users typically have userPrincipalName; groups/SPs counted separately
        upn = obj.get("userPrincipalName")
        account_enabled = obj.get("accountEnabled")

        if upn is None and "user" not in odata.lower():
            # group or service principal holding a role
            if obj:
                non_user_principals += 1
            else:
                disabled_or_unknown += 1
            continue

        if account_enabled is False:
            disabled_or_unknown += 1
            continue

        if pid in recent_signins:
            active_users += 1
            continue

        # Enabled user (or unknown type with UPN) without recent success sign-in
        dormant_users.append(
            {
                "id": pid,
                # Redact local-part in default evidence for safer reports
                "userPrincipalName": _redact_upn(str(upn)) if upn else pid,
            }
        )

    evidence_out = {
        "privileged_principal_count": len(principal_ids),
        "active_privileged_users": active_users,
        "dormant_privileged_users": len(dormant_users),
        "non_user_privileged_principals": non_user_principals,
        "disabled_or_unresolved": disabled_or_unknown,
        "lookback_days": lookback_days,
        "signin_sample_truncated": signin_truncated,
        "dormant_sample": dormant_users[:10],
    }

    if not principal_ids:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="No privileged role principals were found to evaluate for dormancy.",
            evidence=evidence_out,
            customer_summary=(
                "We could not list high-privilege accounts to check for inactivity."
            ),
        )

    if not dormant_users:
        summary = (
            f"No enabled privileged users without successful sign-in in "
            f"{lookback_days} days were found "
            f"({active_users} active privileged user(s) observed)."
        )
        if signin_truncated:
            summary += " Sign-in sampling was truncated; results may be incomplete."
        return Evaluation(
            status=FindingStatus.OK if not signin_truncated else FindingStatus.PARTIAL,
            summary=summary,
            evidence=evidence_out,
            customer_summary=(
                "High-privilege accounts we could check appear to have been used "
                "recently (or are disabled)."
                + (
                    " Note: sign-in history sampling was limited in large tenants."
                    if signin_truncated
                    else ""
                )
            ),
        )

    status = FindingStatus.GAP if len(dormant_users) >= 2 else FindingStatus.PARTIAL
    return Evaluation(
        status=status,
        summary=(
            f"Found {len(dormant_users)} enabled privileged user(s) with no successful "
            f"sign-in in the last {lookback_days} days "
            f"(of {len(principal_ids)} privileged principal(s))."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Some powerful accounts are still switched on but have not been used "
            "recently. Unused admin accounts are a favorite target for attackers."
        ),
    )


def _redact_upn(upn: str) -> str:
    if "@" not in upn:
        return "***"
    local, _, domain = upn.partition("@")
    if not local:
        return f"***@{domain}"
    return f"{local[0]}***@{domain}"


def _score_status(ratio: float | None, *, matched: int) -> FindingStatus:
    if matched <= 0 or ratio is None:
        return FindingStatus.PARTIAL
    if ratio >= 0.85:
        return FindingStatus.OK
    if ratio >= 0.45:
        return FindingStatus.PARTIAL
    return FindingStatus.GAP


def evaluate_mdo_p2_policies(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess MDO-oriented Secure Score controls (Safe Links/Attachments proxy)."""
    del check
    from licenselens.collectors.secure_score import MDO_CONTROL_HINTS, summarize_controls

    controls = list(evidence.get("secure_score_controls") or [])
    summary = summarize_controls(controls, MDO_CONTROL_HINTS)
    ratio = summary.get("ratio")
    matched = int(summary.get("matched_count") or 0)

    evidence_out = {
        "source": "secureScore.controlScores",
        "matched_controls": matched,
        "score_ratio": ratio,
        "controls": summary.get("controls") or [],
        "note": (
            "Uses Microsoft Secure Score control signals as a proxy for "
            "Defender for Office 365 policy enforcement when direct policy "
            "APIs are unavailable."
        ),
    }

    if matched == 0:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "No Defender for Office 365–related Secure Score controls were "
                "found. Unable to confirm Safe Links/Attachments enforcement."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could not automatically confirm whether extra email "
                "protections are turned on. Ask IT to verify Safe Links and "
                "Safe Attachments for all users."
            ),
        )

    status = _score_status(float(ratio) if ratio is not None else None, matched=matched)
    pct = f"{float(ratio) * 100:.0f}%" if ratio is not None else "n/a"
    if status == FindingStatus.OK:
        return Evaluation(
            status=status,
            summary=(
                f"Secure Score shows strong MDO-related control completion "
                f"({matched} controls, ~{pct} of matched max score)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Extra email protections look largely enabled based on Microsoft's "
                "security score signals."
            ),
        )
    if status == FindingStatus.PARTIAL:
        return Evaluation(
            status=status,
            summary=(
                f"Secure Score shows partial MDO-related control completion "
                f"({matched} controls, ~{pct}). Safe Links/Attachments may be "
                "incomplete or not fully enforced."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Some stronger email protections appear configured, but not fully. "
                "Safe Links and Safe Attachments may still miss people or stay in "
                "test mode."
            ),
        )
    return Evaluation(
        status=status,
        summary=(
            f"Secure Score shows weak MDO-related control completion "
            f"({matched} controls, ~{pct}) despite Defender for Office licensing."
        ),
        evidence=evidence_out,
        customer_summary=(
            "You appear to pay for stronger email protection, but Microsoft's "
            "score signals suggest much of it is not turned on yet."
        ),
    )


def evaluate_mde_onboard_gap(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Compare MDE licensed units vs onboarded machines."""
    del check
    summary = dict(evidence.get("mde_summary") or {})
    licensed = summary.get("licensed_units")
    onboarded = summary.get("onboarded_machines")
    truncated = bool(summary.get("truncated"))

    if onboarded is None:
        return Evaluation(
            status=FindingStatus.ERROR,
            summary="Defender for Endpoint machine inventory was not available.",
            evidence=summary,
            customer_summary=(
                "We could not read device enrollment numbers for advanced PC "
                "protection. This is often a missing API permission."
            ),
        )

    onboarded_i = int(onboarded)
    evidence_out = {
        **summary,
        "coverage_ratio": (
            (onboarded_i / int(licensed)) if licensed and int(licensed) > 0 else None
        ),
    }

    if licensed is None or int(licensed) <= 0:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Found {onboarded_i} Defender for Endpoint machine(s), but could "
                "not determine licensed unit count from SKUs."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Devices are enrolled in advanced protection, but we could not "
                "compare that number to purchased seats automatically."
            ),
        )

    licensed_i = int(licensed)
    ratio = onboarded_i / licensed_i if licensed_i else 0.0
    evidence_out["coverage_ratio"] = ratio

    if ratio >= 0.85 and not truncated:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"Defender for Endpoint coverage looks healthy: "
                f"{onboarded_i} onboarded vs ~{licensed_i} licensed units "
                f"({ratio * 100:.0f}%)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Most paid device-protection seats appear matched by enrolled devices."
            ),
        )

    if ratio >= 0.5:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Partial Defender for Endpoint onboarding: {onboarded_i} onboarded "
                f"vs ~{licensed_i} licensed units ({ratio * 100:.0f}%)."
                + (" Machine count may be truncated." if truncated else "")
            ),
            evidence=evidence_out,
            customer_summary=(
                "Some PCs are enrolled in advanced protection, but a noticeable "
                "share of paid seats still look unused."
            ),
        )

    return Evaluation(
        status=FindingStatus.GAP,
        summary=(
            f"Large Defender for Endpoint onboarding gap: {onboarded_i} onboarded "
            f"vs ~{licensed_i} licensed units ({ratio * 100:.0f}%)."
            + (" Machine count may be truncated." if truncated else "")
        ),
        evidence=evidence_out,
        customer_summary=(
            "You appear to pay for advanced device protection on many seats, but "
            "relatively few devices are enrolled."
        ),
    )


def evaluate_mdi_sensors(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess Defender for Identity posture via Secure Score control signals."""
    del check
    from licenselens.collectors.secure_score import MDI_CONTROL_HINTS, summarize_controls

    controls = list(evidence.get("secure_score_controls") or [])
    summary = summarize_controls(controls, MDI_CONTROL_HINTS)
    ratio = summary.get("ratio")
    matched = int(summary.get("matched_count") or 0)
    evidence_out = {
        "source": "secureScore.controlScores",
        "matched_controls": matched,
        "score_ratio": ratio,
        "controls": summary.get("controls") or [],
        "note": (
            "Defender for Identity sensor health is approximated from Secure Score "
            "controls when the MDI API is not configured."
        ),
    }

    if matched == 0:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "No Defender for Identity–related Secure Score controls were found. "
                "Cannot confirm sensor deployment from this signal alone."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could not confirm whether on-site directory attack sensors are "
                "installed. If you still run office domain controllers, ask IT to verify."
            ),
        )

    status = _score_status(float(ratio) if ratio is not None else None, matched=matched)
    pct = f"{float(ratio) * 100:.0f}%" if ratio is not None else "n/a"
    if status == FindingStatus.OK:
        cust = (
            "On-site directory protection signals look healthy based on "
            "Microsoft's security score."
        )
    elif status == FindingStatus.PARTIAL:
        cust = (
            "Some Defender for Identity protections appear configured, but "
            "coverage may be incomplete."
        )
    else:
        cust = (
            "You may be paying for directory attack sensors that are missing or "
            "unhealthy."
        )
    return Evaluation(
        status=status,
        summary=(
            f"Defender for Identity–related Secure Score completion ~{pct} "
            f"across {matched} control(s)."
        ),
        evidence=evidence_out,
        customer_summary=cust,
    )


def evaluate_sen_analytics_coverage(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess enabled Sentinel analytics rule density and tactic coverage."""
    del check
    if evidence.get("sentinel_workspace_missing"):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=(
                "Sentinel workspace was not provided. Pass --workspace-resource-id "
                "or subscription/resource-group/workspace-name to evaluate analytics rules."
            ),
            evidence={"hint": "workspace_required"},
            customer_summary=(
                "We found Sentinel licensing signals, but need the security workspace "
                "location to check whether alarms are turned on."
            ),
        )

    rules = dict(evidence.get("sentinel_rules") or {})
    if evidence.get("sentinel_rules_error"):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=f"Could not read Sentinel analytics rules: {evidence['sentinel_rules_error']}",
            evidence=rules,
            customer_summary=(
                "We could not read detection rules in your security workspace. "
                "This is often missing Azure permissions on the workspace."
            ),
        )

    enabled = int(rules.get("enabled_scheduled_or_nrt") or rules.get("enabled_rules") or 0)
    total = int(rules.get("total_rules") or 0)
    tactics = int(rules.get("tactic_count") or 0)
    evidence_out = dict(rules)

    if total == 0 and enabled == 0:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No Sentinel analytics rules were found in the workspace.",
            evidence=evidence_out,
            customer_summary=(
                "Your security command center appears empty — few or no detection "
                "alarms are configured."
            ),
        )

    if enabled == 0:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=f"Found {total} analytics rule(s) but none are enabled.",
            evidence=evidence_out,
            customer_summary=(
                "Detection rules exist but are turned off, so the workspace is not "
                "actively watching for threats."
            ),
        )

    if enabled >= 10 and tactics >= 3:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"Sentinel analytics coverage looks healthy: {enabled} enabled "
                f"scheduled/NRT rule(s) across {tactics} MITRE tactic(s)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Your security workspace has a solid set of alarms turned on across "
                "multiple attack stages."
            ),
        )

    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=(
            f"Thin Sentinel analytics coverage: {enabled} enabled scheduled/NRT "
            f"rule(s), {tactics} tactic(s) (total rules={total})."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Some detection alarms are on, but coverage still looks light for a "
            "paid security command center."
        ),
    )


def evaluate_sen_ueba(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess Sentinel UEBA / entity analytics enablement."""
    del check
    if evidence.get("sentinel_workspace_missing"):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=(
                "Sentinel workspace was not provided. Pass --workspace-resource-id "
                "to evaluate UEBA / entity analytics."
            ),
            evidence={"hint": "workspace_required"},
            customer_summary=(
                "We need the security workspace location to check behavior analytics."
            ),
        )

    ueba = dict(evidence.get("sentinel_ueba") or {})
    if evidence.get("sentinel_ueba_error") and not ueba:
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=f"Could not read Sentinel settings: {evidence['sentinel_ueba_error']}",
            evidence=ueba,
            customer_summary=(
                "We could not verify behavior analytics settings on the workspace."
            ),
        )

    if ueba.get("settings_error") and ueba.get("ueba_enabled") is False and not ueba.get(
        "raw_entity_present"
    ):
        # Could not read settings — distinguish from explicitly off
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=f"Sentinel settings read failed: {ueba.get('settings_error')}",
            evidence=ueba,
            customer_summary=(
                "Behavior analytics status could not be verified (permissions or API)."
            ),
        )

    if ueba.get("ueba_enabled"):
        return Evaluation(
            status=FindingStatus.OK,
            summary="Sentinel UEBA / entity analytics appears enabled.",
            evidence=ueba,
            customer_summary=(
                "Behavior-based detection looks turned on in your security workspace."
            ),
        )

    return Evaluation(
        status=FindingStatus.GAP,
        summary="Sentinel UEBA / entity analytics does not appear enabled.",
        evidence=ueba,
        customer_summary=(
            "Behavior analytics that learn normal patterns for people and devices "
            "still looks switched off."
        ),
    )


def evaluate_purview_dlp(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess DLP enforcement using Secure Score proxy (and optional Graph)."""
    del check
    bundle = dict(evidence.get("purview_dlp") or {})
    score = dict(bundle.get("dlp_secure_score") or {})
    matched = int(score.get("matched_count") or 0)
    ratio = score.get("ratio")
    weak = int(score.get("weak_control_count") or 0)
    evidence_out = {
        **bundle,
        "note": (
            "Uses Microsoft Secure Score DLP/information-protection controls as a "
            "proxy when direct Purview policy APIs are unavailable to the app."
        ),
    }

    if matched == 0:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "No DLP-related Secure Score controls were found; cannot confirm "
                "Purview DLP enforcement automatically."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could not automatically confirm data-leak guardrails. Ask IT "
                "whether DLP policies are enforced for email and files."
            ),
        )

    r = float(ratio) if ratio is not None else 0.0
    # Never claim confident OK on weak proxy alone unless score is very high
    if r >= 0.85 and weak == 0:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"Secure Score DLP-related controls look strong "
                f"({matched} controls, ~{r * 100:.0f}% of matched max)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Data-leak guardrails appear largely enabled based on Microsoft's "
                "security score signals."
            ),
        )

    if r >= 0.4:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Secure Score suggests partial DLP posture "
                f"({matched} controls, ~{r * 100:.0f}%; weak={weak})."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Some data-protection rules may exist, but enforcement still looks "
                "incomplete or stuck in testing."
            ),
        )

    return Evaluation(
        status=FindingStatus.GAP,
        summary=(
            f"Secure Score suggests DLP is largely unused "
            f"({matched} controls, ~{r * 100:.0f}% completion)."
        ),
        evidence=evidence_out,
        customer_summary=(
            "You appear to pay for data-leak protection that is not meaningfully "
            "enforced yet."
        ),
    )


EVALUATORS: dict[str, Evaluator] = {
    "id-ca-priv-gaps": evaluate_ca_priv_gaps,
    "id-idprotect-off": evaluate_idprotect_off,
    "id-pim-unused": evaluate_pim_unused,
    "id-dormant-privileged": evaluate_dormant_privileged,
    "mdo-p2-policies-default": evaluate_mdo_p2_policies,
    "mde-onboard-gap": evaluate_mde_onboard_gap,
    "mdi-sensors-missing": evaluate_mdi_sensors,
    "sen-analytics-rule-coverage": evaluate_sen_analytics_coverage,
    "sen-ueba-not-enabled": evaluate_sen_ueba,
    "pur-dlp-not-enforced": evaluate_purview_dlp,
}
