"""Finding construction helpers for scan evaluation."""

from __future__ import annotations

from typing import Any

from licenselens.engine.evaluate import Evaluation
from licenselens.engine.quality import apply_quality_policy
from licenselens.models import (
    STATUS_PLAIN_LABELS,
    CheckDefinition,
    Confidence,
    ExposureClass,
    Finding,
    FindingStatus,
)
from licenselens.schema_contracts import EvaluationMode

STATUS_PRIORITY = {
    FindingStatus.GAP: 0,
    FindingStatus.PARTIAL: 1,
    FindingStatus.SKIPPED: 2,
    FindingStatus.ERROR: 3,
    FindingStatus.OK: 4,
    FindingStatus.NOT_LICENSED: 5,
}

#: Severity-ordered statuses for the post-scan finding summary.
SUMMARY_STATUS_ORDER: tuple[str, ...] = (
    FindingStatus.GAP.value,
    FindingStatus.PARTIAL.value,
    FindingStatus.ERROR.value,
    FindingStatus.SKIPPED.value,
    FindingStatus.NOT_LICENSED.value,
    FindingStatus.OK.value,
)


def status_count_rows(counts: dict[str, int]) -> list[tuple[str, str, int]]:
    """Ordered (status, plain label, count) rows for the post-scan summary.

    Known statuses render first in severity order; unknown statuses follow
    alphabetically so nothing is ever dropped from the summary.
    """
    rows: list[tuple[str, str, int]] = []
    for status in SUMMARY_STATUS_ORDER:
        count = counts.get(status, 0)
        if count:
            rows.append((status, STATUS_PLAIN_LABELS.get(status, status), count))
    for status, count in sorted(counts.items()):
        if status not in SUMMARY_STATUS_ORDER and count:
            rows.append((status, STATUS_PLAIN_LABELS.get(status, status), count))
    return rows


def eligible(check: CheckDefinition, owned: set[str]) -> bool:
    if not check.required_capabilities:
        return True
    return any(cap in owned for cap in check.required_capabilities)


def customer_fields(check: CheckDefinition) -> dict[str, str]:
    return {
        "customer_title": check.customer_title or check.title,
        "customer_summary": check.customer_summary or check.description,
        "customer_next_step": check.customer_next_step or check.remediation,
        "why_it_matters": check.why_it_matters,
    }


def finding_evaluation_mode(
    check: CheckDefinition, evidence: dict[str, Any] | None
) -> EvaluationMode:
    import importlib

    try:
        registry = importlib.import_module("licenselens.engine.runner").default_registry()
        mode = registry.evaluator_for(check.id).evaluation_mode
    except KeyError:
        mode = EvaluationMode.DIRECT
    payload = evidence or {}
    if mode is EvaluationMode.DIRECT_WITH_PROXY_FALLBACK:
        if payload.get("proxy") is False or payload.get("exchange_direct") is True:
            return EvaluationMode.DIRECT
        return EvaluationMode.PROXY
    if mode is EvaluationMode.PROXY and payload.get("proxy") is False:
        return EvaluationMode.DIRECT
    return mode


def base_finding(
    check: CheckDefinition,
    *,
    status: FindingStatus,
    summary: str,
    owned: set[str],
    evidence: dict[str, Any] | None = None,
    customer_summary: str | None = None,
    customer_next_step: str | None = None,
    confidence: Confidence = Confidence.MEDIUM,
    data_sources: list[str] | None = None,
    limitations: list[str] | None = None,
    strict_proxy: bool = True,
) -> Finding:
    customer = customer_fields(check)
    finding = Finding(
        check_id=check.id,
        title=check.title,
        workload=check.workload,
        status=status,
        severity=check.severity,
        value_impact=check.value_impact,
        impact=check.impact,
        effort=check.effort,
        blast_radius=check.blast_radius,
        pack=check.pack,
        exposure_class=check.exposure_class,
        deep_link=check.deep_link,
        summary=summary,
        customer_title=customer["customer_title"],
        customer_summary=customer_summary or customer["customer_summary"],
        customer_next_step=customer_next_step or customer["customer_next_step"],
        why_it_matters=customer["why_it_matters"],
        status_label=STATUS_PLAIN_LABELS[status.value],
        evidence=evidence or {},
        entitlements_used=[c for c in check.required_capabilities if c in owned],
        remediation=check.remediation,
        references=check.references,
        confidence=confidence,
        data_sources=list(data_sources or []),
        limitations=list(limitations or []),
        evaluation_mode=finding_evaluation_mode(check, evidence),
    )
    finding = apply_quality_policy(finding, strict_proxy=strict_proxy)
    finding.status_label = STATUS_PLAIN_LABELS.get(finding.status.value, finding.status.value)
    return finding


def not_licensed_finding(
    check: CheckDefinition, owned: set[str], *, strict_proxy: bool = True
) -> Finding:
    return base_finding(
        check,
        status=FindingStatus.NOT_LICENSED,
        summary=("Required capability not detected in tenant entitlements; check skipped."),
        owned=owned,
        customer_summary=(
            "This protection does not appear to be included in the licenses "
            "we detected, so there is nothing to configure for it yet."
        ),
        customer_next_step=(
            "If you expected this capability, confirm the correct Microsoft "
            "plan is assigned, or talk to your licensing partner."
        ),
        evidence={},
        confidence=Confidence.HIGH,
        data_sources=["graph.subscribedSkus"],
        strict_proxy=strict_proxy,
    )


def skipped_finding(
    check: CheckDefinition, owned: set[str], *, strict_proxy: bool = True
) -> Finding:
    source = check.source_path
    if source:
        source = source.replace("\\", "/").split("/checks/")[-1]
        if not source.startswith("checks/"):
            source = f"checks/{source}" if "checks/" not in source else source
    return base_finding(
        check,
        status=FindingStatus.SKIPPED,
        summary=("Entitlements resolved, but this control check is not implemented yet."),
        owned=owned,
        evidence={"collector": check.collector, "source": source},
        confidence=Confidence.LOW,
        strict_proxy=strict_proxy,
    )


def error_finding(
    check: CheckDefinition,
    owned: set[str],
    message: str,
    *,
    strict_proxy: bool = True,
) -> Finding:
    return base_finding(
        check,
        status=FindingStatus.ERROR,
        summary=f"Could not evaluate check: {message}",
        owned=owned,
        customer_summary=(
            "We could not verify this protection automatically. This is often a "
            "permissions issue — see the technical summary and app registration guide."
        ),
        customer_next_step=(
            "Ask IT to confirm required permissions with admin consent "
            "(docs/permissions.md), then re-run doctor and scan."
        ),
        evidence={"error": message},
        confidence=Confidence.LOW,
        strict_proxy=strict_proxy,
    )


def from_evaluation(
    check: CheckDefinition,
    owned: set[str],
    evaluation: Evaluation,
    *,
    strict_proxy: bool = True,
) -> Finding:
    finding = base_finding(
        check,
        status=evaluation.status,
        summary=evaluation.summary,
        owned=owned,
        evidence=evaluation.evidence,
        customer_summary=evaluation.customer_summary,
        confidence=evaluation.confidence,
        data_sources=evaluation.data_sources,
        limitations=evaluation.limitations,
        strict_proxy=strict_proxy,
    )
    if evaluation.exposure_class != ExposureClass.NONE:
        finding.exposure_class = evaluation.exposure_class
    return finding


def recommended_next_steps(findings: list[Finding], limit: int = 5) -> list[str]:
    actionable = [
        f
        for f in findings
        if f.status in {FindingStatus.GAP, FindingStatus.PARTIAL, FindingStatus.SKIPPED}
        and f.customer_next_step
    ]
    actionable.sort(
        key=lambda f: (
            STATUS_PRIORITY.get(f.status, 99),
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity.value, 9),
        )
    )
    steps: list[str] = []
    seen: set[str] = set()
    for finding in actionable:
        step = finding.customer_next_step.strip()
        if not step or step in seen:
            continue
        seen.add(step)
        steps.append(step)
        if len(steps) >= limit:
            break
    return steps
