"""Identity Protection evaluators."""

from __future__ import annotations

from typing import Any, Final

from licenselens.collectors import conditional_access as ca
from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, FindingStatus

_RISKY_SP_STATES: Final = frozenset(
    {"atrisk", "detected", "confirmed", "confirmedcompromised"}
)
_HANDLED_SP_STATES: Final = frozenset({"dismissed", "remediated", "none"})
_DENIED_MARKERS: Final = ("403", "denied", "authorization", "access denied")


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
            levels = ca.sign_in_risk_levels(p) if kind == "sign_in" else ca.user_risk_levels(p)
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
            levels = ca.sign_in_risk_levels(p) if kind == "sign_in" else ca.user_risk_levels(p)
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


def evaluate_identity_protection_workload(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Workload Identity Protection: no service principals are risky/compromised."""
    del check

    error = evidence.get("risky_service_principals_error")
    if error:
        reason = str(error)
        if any(marker in reason.lower() for marker in _DENIED_MARKERS):
            return Evaluation(
                status=FindingStatus.ERROR,
                summary="Risky service principals could not be read: " + reason,
                evidence={"error": reason},
            )
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "Risky service principals could not be read, so workload "
                "identity risk could not be verified: " + reason
            ),
            evidence={"error": reason},
            customer_summary=(
                "We could not check the risk state of your app and automation "
                "accounts, so please confirm them in Entra ID Protection."
            ),
        )

    items = [
        sp for sp in evidence.get("risky_service_principals") or [] if isinstance(sp, dict)
    ]
    risky: list[dict[str, Any]] = []
    compromised: list[dict[str, Any]] = []
    unclassified: list[dict[str, Any]] = []
    for sp in items:
        state = str(sp.get("riskState") or "").lower()
        if state in _RISKY_SP_STATES:
            risky.append(sp)
            if state == "confirmedcompromised":
                compromised.append(sp)
        elif state in _HANDLED_SP_STATES:
            continue
        else:
            unclassified.append(sp)

    evidence_out = {
        "service_principal_count": len(items),
        "risky_service_principal_count": len(risky),
        "compromised_service_principal_count": len(compromised),
        "unclassified_service_principal_count": len(unclassified),
        "risky_service_principals": [
            {
                "displayName": sp.get("displayName"),
                "appId": sp.get("appId"),
                "riskLevel": sp.get("riskLevel"),
                "riskState": sp.get("riskState"),
            }
            for sp in risky[:10]
        ],
    }

    if risky:
        detail = ", ".join(
            f"{sp.get('displayName') or sp.get('appId') or 'unnamed'} "
            f"({(sp.get('riskState') or 'risky').lower()})"
            for sp in risky[:5]
        )
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"{len(risky)} service principal(s) are flagged as risky or "
                f"compromised: {detail}."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Some app or automation accounts look compromised or risky "
                "right now — an attacker may be using stolen app credentials."
            ),
        )

    if unclassified:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(items)} service principal(s) were read, but "
                f"{len(unclassified)} have an unknown risk state — the tenant "
                "could not be confirmed clean."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could read the workload identity list, but some risk "
                "states were unclear, so please spot-check them in the portal."
            ),
        )

    return Evaluation(
        status=FindingStatus.OK,
        summary=(
            f"Read {len(items)} service principal(s); none are flagged as "
            "risky or compromised."
        ),
        evidence=evidence_out,
        customer_summary=(
            "No app or automation account is currently flagged as risky or "
            "compromised by workload identity protection."
        ),
    )
