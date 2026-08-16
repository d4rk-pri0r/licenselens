"""Purview workload evaluators (direct Graph evidence with proxy fallback)."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus


def evaluate_purview_dlp(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess DLP enforcement from Graph policies; Secure Score as fallback proxy."""
    del check
    bundle = dict(evidence.get("purview_dlp") or {})
    graph = bundle.get("dlp_graph")

    if isinstance(graph, dict) and graph.get("direct"):
        return _evaluate_dlp_direct(graph, bundle)

    return _evaluate_dlp_proxy(bundle)


def _evaluate_dlp_direct(
    graph: dict[str, Any],
    bundle: dict[str, Any],
) -> Evaluation:
    policy_count = int(graph.get("policy_count") or 0)
    enforced = int(graph.get("enforced_count") or 0)
    apps = graph.get("apps") or {}
    evidence_out = {
        **bundle,
        "dlp_graph": graph,
        "proxy": False,
        "direct": True,
    }
    direct_meta = {
        "confidence": Confidence.HIGH,
        "data_sources": ["graph.security.dataLossPreventionPolicies"],
        "limitations": [],
    }

    if policy_count == 0:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "No DLP policies exist in the tenant. The data-loss-prevention "
                "entitlement is not enforced anywhere."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Your plan includes data-leak protection, but no DLP policies are "
                "configured. Deploy at least one policy and move it to enforce mode."
            ),
            **direct_meta,
        )

    if enforced == 0:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"{policy_count} DLP policy(ies) exist but none are in production/"
                "enforce mode (all test/simulation)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "DLP policies exist but are still in test mode, so nothing is "
                "actually blocked or alerted. Move tuned policies to enforce mode."
            ),
            **direct_meta,
        )

    app_count = apps.get("count") if isinstance(apps, dict) else None
    summary = (
        f"{enforced} of {policy_count} DLP policy(ies) run in production mode"
        + (f"; {app_count} monitored app location(s)" if app_count else "")
        + "."
    )
    return Evaluation(
        status=FindingStatus.OK,
        summary=summary,
        evidence=evidence_out,
        customer_summary=(
            "Data-leak guardrails are enforced in production. Keep policy coverage "
            "aligned with the data your people actually handle."
        ),
        **direct_meta,
    )


def _evaluate_dlp_proxy(bundle: dict[str, Any]) -> Evaluation:
    score = dict(bundle.get("dlp_secure_score") or {})
    matched = int(score.get("matched_count") or 0)
    ratio = score.get("ratio")
    weak = int(score.get("weak_control_count") or 0)
    evidence_out = {
        **bundle,
        "proxy": True,
        "note": (
            "Uses Microsoft Secure Score DLP/information-protection controls as a "
            "proxy when direct Purview policy APIs are unavailable to the app."
        ),
    }
    proxy_meta = dict(
        confidence=Confidence.LOW,
        data_sources=["secureScore.controlScores (proxy)"],
        limitations=["Secure Score proxy — verify DLP enforce mode in Purview portal."],
    )

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
            **proxy_meta,
        )

    r = float(ratio) if ratio is not None else 0.0
    if r >= 0.85 and weak == 0:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Secure Score DLP-related controls look strong "
                f"({matched} controls, ~{r * 100:.0f}%) — provisional until portal verify."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Score signals suggest data-leak guardrails are largely on — confirm "
                "enforce mode in the Purview portal."
            ),
            **proxy_meta,
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
                "incomplete or stuck in testing. Verify in the portal."
            ),
            **proxy_meta,
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
            "enforced yet. Confirm in the Purview portal."
        ),
        **proxy_meta,
    )


def evaluate_pur_ediscovery_readiness(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess eDiscovery readiness from Premium eDiscovery cases (Graph v1.0)."""
    del check
    bundle = evidence.get("purview_ediscovery")
    direct_meta = {
        "confidence": Confidence.HIGH,
        "data_sources": ["graph.security.cases.ediscoveryCases"],
    }
    if not isinstance(bundle, dict):
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="eDiscovery case evidence was not collected; readiness unverified.",
            evidence={"purview_ediscovery": None},
            customer_summary=(
                "We could not confirm eDiscovery readiness automatically. "
                "Confirm case and hold workflows in the Purview portal."
            ),
            confidence=Confidence.LOW,
            limitations=["Purview eDiscovery read unavailable — verify in the portal."],
        )

    case_count = int(bundle.get("case_count") or 0)
    if case_count > 0:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"{case_count} Premium eDiscovery case(s) found — case and hold "
                "workflows are in use."
            ),
            evidence=dict(bundle, direct=True),
            customer_summary=(
                "eDiscovery is configured and has been exercised. Keep case access "
                "and legal-hold reviews on a regular cadence."
            ),
            **direct_meta,
        )

    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=(
            "The eDiscovery API returned no Premium cases. Either none exist yet, "
            "or the scanning identity lacks case visibility."
        ),
        evidence=dict(bundle, direct=True),
        customer_summary=(
            "We could not confirm eDiscovery is in use. Create a test case with a "
            "legal hold, and confirm the scanning app is an eDiscovery Administrator."
        ),
        confidence=Confidence.MEDIUM,
        data_sources=["graph.security.cases.ediscoveryCases"],
        limitations=[
            "An empty case list is ambiguous: no Premium cases, or the identity "
            "is not an eDiscovery Administrator/member of any case. Verify in the portal."
        ],
    )


def evaluate_pur_insider_risk_readiness(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess insider risk readiness from IRM policies (Graph beta)."""
    del check
    bundle = evidence.get("purview_insider_risk")
    if not isinstance(bundle, dict):
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Insider risk policy evidence was not collected; readiness unverified.",
            evidence={"purview_insider_risk": None},
            customer_summary=(
                "We could not confirm insider risk readiness automatically. "
                "Confirm a live policy and analytics in the Purview portal."
            ),
            confidence=Confidence.LOW,
            limitations=["Insider risk read unavailable — verify in the portal."],
        )

    policy_count = int(bundle.get("policy_count") or 0)
    if policy_count == 0:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "No Insider Risk Management policies exist — the entitlement is "
                "licensed but unused."
            ),
            evidence=dict(bundle, direct=True),
            customer_summary=(
                "Your plan includes insider risk protection, but no policy is "
                "live. Start with a data-theft-by-departing-users template."
            ),
            confidence=Confidence.HIGH,
            data_sources=["graph.beta.security.insiderRiskManagement.policies"],
            limitations=["Analytics state is not exposed by this API; confirm it in the portal."],
        )

    return Evaluation(
        status=FindingStatus.OK,
        summary=f"{policy_count} Insider Risk Management policy(ies) found.",
        evidence=dict(bundle, direct=True),
        customer_summary=(
            "Insider risk policies are live. Confirm analytics is enabled and "
            "policy scope matches your riskiest groups."
        ),
        confidence=Confidence.HIGH,
        data_sources=["graph.beta.security.insiderRiskManagement.policies"],
        limitations=["Analytics state is not exposed by this API; confirm it in the portal."],
    )
