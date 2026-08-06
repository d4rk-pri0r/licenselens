"""Orchestrate a scan: entitlements → eligible checks → findings."""

from __future__ import annotations

from datetime import UTC, datetime

from licenselens import __version__
from licenselens.auth import AuthContext
from licenselens.catalog.loader import load_capabilities, resolve_owned_capabilities
from licenselens.collectors.skus import collect_subscribed_skus
from licenselens.engine.loader import load_checks
from licenselens.models import (
    CheckDefinition,
    Finding,
    FindingStatus,
    ScanResult,
    Workload,
)


def _eligible(check: CheckDefinition, owned: set[str]) -> bool:
    if not check.required_capabilities:
        return True
    return any(cap in owned for cap in check.required_capabilities)


def _placeholder_finding(check: CheckDefinition, owned: set[str]) -> Finding:
    """v0.1a: emit structured placeholders until collectors are implemented."""
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
        evidence={"collector": check.collector, "source": check.source_path},
        entitlements_used=[c for c in check.required_capabilities if c in owned],
        remediation=check.remediation,
        references=check.references,
    )


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

    checks = [c for c in load_checks() if c.enabled]
    if workloads:
        wanted = set(workloads)
        checks = [c for c in checks if c.workload in wanted]

    findings = [_placeholder_finding(c, owned_set) for c in checks]

    return ScanResult(
        version=__version__,
        tenant_id=auth.tenant_id,
        scanned_at=datetime.now(UTC).isoformat(),
        owned_capabilities=owned,
        subscribed_skus=skus,
        findings=findings,
    )
