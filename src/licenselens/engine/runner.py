"""Orchestrate a scan: entitlements → eligible checks → findings."""

from __future__ import annotations

from datetime import UTC, datetime

from licenselens import __version__
from licenselens.auth import AuthContext
from licenselens.catalog.loader import (
    capability_summaries_for,
    load_capabilities,
    resolve_owned_capabilities,
)
from licenselens.collectors.skus import collect_subscribed_skus
from licenselens.engine.loader import load_checks
from licenselens.models import (
    STATUS_PLAIN_LABELS,
    CheckDefinition,
    Finding,
    FindingStatus,
    ScanResult,
    Workload,
)

_STATUS_PRIORITY = {
    FindingStatus.GAP: 0,
    FindingStatus.PARTIAL: 1,
    FindingStatus.SKIPPED: 2,
    FindingStatus.ERROR: 3,
    FindingStatus.OK: 4,
    FindingStatus.NOT_LICENSED: 5,
}


def _eligible(check: CheckDefinition, owned: set[str]) -> bool:
    if not check.required_capabilities:
        return True
    return any(cap in owned for cap in check.required_capabilities)


def _customer_fields(check: CheckDefinition) -> dict[str, str]:
    return {
        "customer_title": check.customer_title or check.title,
        "customer_summary": check.customer_summary or check.description,
        "customer_next_step": check.customer_next_step or check.remediation,
    }


def _placeholder_finding(check: CheckDefinition, owned: set[str]) -> Finding:
    """v0.1a: emit structured placeholders until collectors are implemented."""
    customer = _customer_fields(check)

    if not _eligible(check, owned):
        return Finding(
            check_id=check.id,
            title=check.title,
            workload=check.workload,
            status=FindingStatus.NOT_LICENSED,
            severity=check.severity,
            value_impact=check.value_impact,
            summary=(
                "Required capability not detected in tenant entitlements; "
                "check skipped."
            ),
            customer_title=customer["customer_title"],
            customer_summary=(
                "This protection does not appear to be included in the licenses "
                "we detected, so there is nothing to configure for it yet."
            ),
            customer_next_step=(
                "If you expected this capability, confirm the correct Microsoft "
                "plan is assigned, or talk to your licensing partner."
            ),
            status_label=STATUS_PLAIN_LABELS[FindingStatus.NOT_LICENSED.value],
            entitlements_used=[],
            remediation=check.remediation,
            references=check.references,
        )

    return Finding(
        check_id=check.id,
        title=check.title,
        workload=check.workload,
        status=FindingStatus.SKIPPED,
        severity=check.severity,
        value_impact=check.value_impact,
        summary=(
            "Check is registered and licensed, but the collector is not "
            "implemented yet (scaffold)."
        ),
        customer_title=customer["customer_title"],
        customer_summary=customer["customer_summary"],
        customer_next_step=customer["customer_next_step"],
        status_label=STATUS_PLAIN_LABELS[FindingStatus.SKIPPED.value],
        evidence={"collector": check.collector, "source": check.source_path},
        entitlements_used=[c for c in check.required_capabilities if c in owned],
        remediation=check.remediation,
        references=check.references,
    )


def _recommended_next_steps(findings: list[Finding], limit: int = 5) -> list[str]:
    """Top plain-language next steps for gaps / partial / pending licensed checks."""
    actionable = [
        f
        for f in findings
        if f.status
        in {FindingStatus.GAP, FindingStatus.PARTIAL, FindingStatus.SKIPPED}
        and f.customer_next_step
    ]
    actionable.sort(
        key=lambda f: (
            _STATUS_PRIORITY.get(f.status, 99),
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                f.severity.value, 9
            ),
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


def run_scan(
    auth: AuthContext,
    *,
    workloads: list[Workload] | None = None,
    dry_run: bool = True,
) -> ScanResult:
    capabilities = load_capabilities()
    skus = collect_subscribed_skus(auth, dry_run=dry_run)
    owned = resolve_owned_capabilities(capabilities, skus)
    owned_set = set(owned)
    summaries = capability_summaries_for(capabilities, owned)

    checks = [c for c in load_checks() if c.enabled]
    if workloads:
        wanted = set(workloads)
        checks = [c for c in checks if c.workload in wanted]

    findings = [_placeholder_finding(c, owned_set) for c in checks]
    findings.sort(
        key=lambda f: (
            _STATUS_PRIORITY.get(f.status, 99),
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                f.severity.value, 9
            ),
            f.check_id,
        )
    )

    return ScanResult(
        version=__version__,
        tenant_id=auth.tenant_id,
        scanned_at=datetime.now(UTC).isoformat(),
        owned_capabilities=owned,
        capability_summaries=summaries,
        subscribed_skus=skus,
        findings=findings,
        recommended_next_steps=_recommended_next_steps(findings),
    )
