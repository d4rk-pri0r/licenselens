"""Quality policy: confidence, proxy demotion, truncation guards."""

from __future__ import annotations

from licenselens.models import (
    CONFIDENCE_PLAIN_LABELS,
    PROXY_CHECK_IDS,
    PROXY_VERIFY_NOTE,
    Confidence,
    Finding,
    FindingStatus,
)


def apply_quality_policy(
    finding: Finding,
    *,
    strict_proxy: bool = True,
) -> Finding:
    """Mutate/return finding with confidence, demotions, and limitation notes."""
    limitations = list(finding.limitations)
    data_sources = list(finding.data_sources)
    confidence = finding.confidence or Confidence.MEDIUM
    status = finding.status
    customer_summary = finding.customer_summary
    summary = finding.summary

    is_proxy = (
        finding.check_id in PROXY_CHECK_IDS
        or bool((finding.evidence or {}).get("proxy"))
        or any("secureScore" in s or "proxy" in s.lower() for s in data_sources)
    )

    if is_proxy:
        confidence = Confidence.LOW
        if "secureScore.controlScores" not in data_sources and not data_sources:
            data_sources.append("secureScore.controlScores (proxy)")
        if PROXY_VERIFY_NOTE not in limitations:
            limitations.append(PROXY_VERIFY_NOTE)
        if strict_proxy and status == FindingStatus.OK:
            status = FindingStatus.PARTIAL
            summary = (
                f"{summary.rstrip('.')} "
                "(capped at partial under strict proxy policy — verify in portal)."
            )
            if customer_summary and PROXY_VERIFY_NOTE.split("—")[0].strip() not in customer_summary:
                customer_summary = f"{customer_summary.rstrip('.')} {PROXY_VERIFY_NOTE}"

    # Truncation / sampling guards
    evidence = finding.evidence or {}
    if evidence.get("signin_sample_truncated"):
        limitations.append(
            "Sign-in history was sampled with a page cap; dormant-account results "
            "may be incomplete on large tenants."
        )
        if confidence == Confidence.HIGH:
            confidence = Confidence.MEDIUM
        if status == FindingStatus.OK:
            status = FindingStatus.PARTIAL
            summary = (
                f"{summary.rstrip('.')} "
                "(not marked fully OK because sign-in sampling was truncated)."
            )

    if evidence.get("truncated") and finding.check_id == "mde-onboard-gap":
        limitations.append(
            "Defender for Endpoint machine inventory pagination was truncated; "
            "onboarded counts may be understated."
        )
        if confidence == Confidence.HIGH:
            confidence = Confidence.MEDIUM
        if status == FindingStatus.OK:
            status = FindingStatus.PARTIAL
            summary = (
                f"{summary.rstrip('.')} "
                "(not marked fully OK because device inventory was truncated)."
            )

    if finding.status == FindingStatus.ERROR:
        confidence = Confidence.LOW
        if not data_sources:
            data_sources.append("unavailable")

    if finding.status == FindingStatus.NOT_LICENSED:
        confidence = Confidence.HIGH
        if not data_sources:
            data_sources.append("graph.subscribedSkus")

    if finding.status == FindingStatus.SKIPPED:
        confidence = Confidence.LOW

    # Defaults for direct checks that didn't set sources
    if not data_sources and finding.check_id.startswith("id-"):
        data_sources.append("microsoft.graph")
        if confidence == Confidence.MEDIUM and finding.status in {
            FindingStatus.GAP,
            FindingStatus.PARTIAL,
            FindingStatus.OK,
        }:
            confidence = Confidence.HIGH

    if finding.check_id.startswith("sen-") and not any("arm" in s for s in data_sources):
        if "azure.arm.securityInsights" not in data_sources:
            data_sources.append("azure.arm.securityInsights")

    if finding.check_id == "mde-onboard-gap" and not any("mde" in s for s in data_sources):
        data_sources.append("mde.api.machines")
        data_sources.append("graph.subscribedSkus")

    finding.status = status
    finding.summary = summary
    finding.customer_summary = customer_summary
    finding.confidence = confidence
    finding.confidence_label = CONFIDENCE_PLAIN_LABELS.get(confidence.value, confidence.value)
    finding.data_sources = list(dict.fromkeys(data_sources))
    finding.limitations = list(dict.fromkeys(limitations))
    finding.status_label = finding.status_label  # refreshed by caller if status changed
    return finding


def scan_level_limitations(findings: list[Finding], *, strict_proxy: bool) -> list[str]:
    notes: list[str] = []
    if strict_proxy:
        notes.append(
            "Strict proxy mode is ON: Secure Score–based checks (MDI, Purview DLP) "
            "never report fully OK and are labeled low confidence. "
            "MDO email is off by default (use --allow-email-proxy for a labeled degraded path)."
        )
    proxy_ids = [f.check_id for f in findings if f.check_id in PROXY_CHECK_IDS]
    if proxy_ids:
        notes.append("Proxy-based checks in this report: " + ", ".join(sorted(proxy_ids)) + ".")
    if any(
        "truncated" in (f.limitations or []) or (f.evidence or {}).get("truncated")
        for f in findings
    ):
        notes.append("One or more checks used truncated samples; see finding limitations.")
    if any(f.status.value == "error" for f in findings):
        notes.append(
            "Some checks could not run (permissions or missing workspace). "
            "See doctor --profile full and docs/permissions.md."
        )
    return notes
