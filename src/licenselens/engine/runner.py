"""Orchestrate a scan: entitlements → eligible checks → findings."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from licenselens import __version__
from licenselens.auth import AuthContext, AuthMode
from licenselens.catalog.loader import (
    capability_summaries_for,
    load_capabilities,
    resolve_owned_capabilities,
)
from licenselens.collectors.conditional_access import DEMO_CA_POLICIES, collect_ca_policies
from licenselens.collectors.privileged_roles import (
    DEMO_PRINCIPAL_DIRECTORY,
    DEMO_RECENT_SIGNIN_USER_IDS,
    DEMO_ROLE_ASSIGNMENTS,
    DEMO_ROLE_ELIGIBILITIES,
    collect_role_assignments,
    collect_role_eligibility_schedules,
    privileged_principal_ids,
)
from licenselens.collectors.signins import (
    collect_directory_objects_by_ids,
    collect_recent_success_signin_user_ids,
)
from licenselens.collectors.skus import collect_subscribed_skus, collect_subscribed_skus_live
from licenselens.engine.evaluate import EVALUATORS, Evaluation
from licenselens.engine.loader import load_checks
from licenselens.errors import GraphError
from licenselens.graph import GraphClient, fetch_organization_context
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


def _base_finding(
    check: CheckDefinition,
    *,
    status: FindingStatus,
    summary: str,
    owned: set[str],
    evidence: dict[str, Any] | None = None,
    customer_summary: str | None = None,
    customer_next_step: str | None = None,
) -> Finding:
    customer = _customer_fields(check)
    return Finding(
        check_id=check.id,
        title=check.title,
        workload=check.workload,
        status=status,
        severity=check.severity,
        value_impact=check.value_impact,
        summary=summary,
        customer_title=customer["customer_title"],
        customer_summary=customer_summary or customer["customer_summary"],
        customer_next_step=customer_next_step or customer["customer_next_step"],
        status_label=STATUS_PLAIN_LABELS[status.value],
        evidence=evidence or {},
        entitlements_used=[c for c in check.required_capabilities if c in owned],
        remediation=check.remediation,
        references=check.references,
    )


def _not_licensed_finding(check: CheckDefinition, owned: set[str]) -> Finding:
    return _base_finding(
        check,
        status=FindingStatus.NOT_LICENSED,
        summary=(
            "Required capability not detected in tenant entitlements; check skipped."
        ),
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
    )


def _skipped_finding(check: CheckDefinition, owned: set[str]) -> Finding:
    source = check.source_path
    if source:
        # Avoid leaking absolute developer paths into portable reports
        source = source.replace("\\", "/").split("/checks/")[-1]
        if not source.startswith("checks/"):
            source = f"checks/{source}" if "checks/" not in source else source
    return _base_finding(
        check,
        status=FindingStatus.SKIPPED,
        summary=(
            "Entitlements resolved, but this control check is not implemented yet."
        ),
        owned=owned,
        evidence={"collector": check.collector, "source": source},
    )


def _error_finding(check: CheckDefinition, owned: set[str], message: str) -> Finding:
    return _base_finding(
        check,
        status=FindingStatus.ERROR,
        summary=f"Could not evaluate check: {message}",
        owned=owned,
        customer_summary=(
            "We could not verify this protection automatically. This is often a "
            "permissions issue — see the technical summary and app registration guide."
        ),
        customer_next_step=(
            "Ask IT to confirm Policy.Read.All (application) is granted with admin "
            "consent, then re-run the scan."
        ),
        evidence={"error": message},
    )


def _from_evaluation(
    check: CheckDefinition,
    owned: set[str],
    evaluation: Evaluation,
) -> Finding:
    return _base_finding(
        check,
        status=evaluation.status,
        summary=evaluation.summary,
        owned=owned,
        evidence=evaluation.evidence,
        customer_summary=evaluation.customer_summary,
    )


def _recommended_next_steps(findings: list[Finding], limit: int = 5) -> list[str]:
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


_CHECK_EVIDENCE_KEYS: dict[str, list[str]] = {
    "id-ca-priv-gaps": ["ca_policies"],
    "id-idprotect-off": ["ca_policies"],
    "id-pim-unused": ["role_assignments", "role_eligibilities"],
    "id-dormant-privileged": [
        "role_assignments",
        "recent_signin_user_ids",
        "principal_directory",
    ],
}


def _gather_evidence(
    *,
    scan_mode: str,
    client: GraphClient | None,
    warnings: list[str],
) -> dict[str, Any]:
    """Collect shared evidence blobs for evaluators."""
    evidence: dict[str, Any] = {
        "signin_lookback_days": 90,
        "signin_sample_truncated": False,
    }

    if scan_mode == "dry_run":
        evidence["ca_policies"] = list(DEMO_CA_POLICIES)
        evidence["role_assignments"] = list(DEMO_ROLE_ASSIGNMENTS)
        evidence["role_eligibilities"] = list(DEMO_ROLE_ELIGIBILITIES)
        evidence["recent_signin_user_ids"] = set(DEMO_RECENT_SIGNIN_USER_IDS)
        evidence["principal_directory"] = dict(DEMO_PRINCIPAL_DIRECTORY)
        return evidence

    assert client is not None
    try:
        evidence["ca_policies"] = collect_ca_policies(client)
    except GraphError as exc:
        warnings.append(f"Conditional Access policies could not be read: {exc}")
        evidence["ca_policies_error"] = str(exc)

    try:
        evidence["role_assignments"] = collect_role_assignments(client)
    except GraphError as exc:
        warnings.append(f"Directory role assignments could not be read: {exc}")
        evidence["role_assignments_error"] = str(exc)

    try:
        evidence["role_eligibilities"] = collect_role_eligibility_schedules(client)
    except GraphError as exc:
        # PIM eligibility may 403 if not licensed / not consented — treat as empty + warn
        warnings.append(
            f"PIM role eligibility schedules could not be read (treating as none): {exc}"
        )
        evidence["role_eligibilities"] = []
        evidence["role_eligibilities_error"] = str(exc)

    assignments = list(evidence.get("role_assignments") or [])
    principal_ids = sorted(privileged_principal_ids(assignments))

    try:
        # Detect truncation: if we hit max pages, flag it
        max_pages = 15
        signin_ids = collect_recent_success_signin_user_ids(
            client, lookback_days=90, max_pages=max_pages
        )
        evidence["recent_signin_user_ids"] = signin_ids
        # Heuristic: very full page budget suggests truncation
        evidence["signin_sample_truncated"] = len(signin_ids) >= max_pages * 400
    except GraphError as exc:
        warnings.append(f"Sign-in logs could not be read: {exc}")
        evidence["recent_signin_error"] = str(exc)

    if principal_ids and "role_assignments_error" not in evidence:
        try:
            evidence["principal_directory"] = collect_directory_objects_by_ids(
                client, principal_ids
            )
        except GraphError as exc:
            warnings.append(f"Privileged principal directory lookup failed: {exc}")
            evidence["principal_directory_error"] = str(exc)
            evidence["principal_directory"] = {}

    return evidence


def _evaluate_check(
    check: CheckDefinition,
    owned: set[str],
    evidence: dict[str, Any],
) -> Finding:
    if not _eligible(check, owned):
        return _not_licensed_finding(check, owned)

    evaluator = EVALUATORS.get(check.id)
    if evaluator is None:
        return _skipped_finding(check, owned)

    required_keys = _CHECK_EVIDENCE_KEYS.get(check.id, [])
    for key in required_keys:
        err_key = f"{key}_error"
        # Map composite keys to error names used above
        if key == "ca_policies" and evidence.get("ca_policies_error"):
            return _error_finding(check, owned, str(evidence["ca_policies_error"]))
        if key == "role_assignments" and evidence.get("role_assignments_error"):
            return _error_finding(check, owned, str(evidence["role_assignments_error"]))
        if key == "recent_signin_user_ids" and evidence.get("recent_signin_error"):
            return _error_finding(check, owned, str(evidence["recent_signin_error"]))
        if key == "principal_directory" and evidence.get("principal_directory_error"):
            return _error_finding(
                check, owned, str(evidence["principal_directory_error"])
            )
        if key not in evidence and err_key not in evidence:
            # role_eligibilities may be missing only on hard failure before set
            if key == "role_eligibilities":
                continue
            return _error_finding(
                check,
                owned,
                f"Required evidence '{key}' was not collected.",
            )

    try:
        result = evaluator(check, evidence)
    except Exception as exc:  # noqa: BLE001
        return _error_finding(check, owned, str(exc))
    return _from_evaluation(check, owned, result)


def run_scan(
    auth: AuthContext,
    *,
    workloads: list[Workload] | None = None,
    dry_run: bool = True,
) -> ScanResult:
    capabilities = load_capabilities()
    warnings = list(auth.warnings)
    tenant_id = auth.tenant_id
    tenant_display_name: str | None = None
    scan_mode = "dry_run" if dry_run or auth.mode == AuthMode.DRY_RUN else "live"
    evidence: dict[str, Any] = {}

    if scan_mode == "dry_run":
        skus = collect_subscribed_skus(auth, dry_run=True)
        evidence = _gather_evidence(scan_mode=scan_mode, client=None, warnings=warnings)
        tenant_id = tenant_id or "00000000-0000-0000-0000-000000000000"
        tenant_display_name = tenant_display_name or "Contoso Demo (dry-run)"
    else:
        with GraphClient(auth) as client:
            try:
                org_id, org_name = fetch_organization_context(client)
                tenant_id = org_id or tenant_id
                tenant_display_name = org_name
            except GraphError as exc:
                warnings.append(f"Could not read organization profile: {exc}")
            try:
                skus = collect_subscribed_skus_live(client)
            except GraphError:
                raise
            evidence = _gather_evidence(
                scan_mode=scan_mode, client=client, warnings=warnings
            )

    owned = resolve_owned_capabilities(capabilities, skus)
    owned_set = set(owned)
    summaries = capability_summaries_for(capabilities, owned)

    checks = [c for c in load_checks() if c.enabled]
    if workloads:
        wanted = set(workloads)
        checks = [c for c in checks if c.workload in wanted]

    findings = [_evaluate_check(c, owned_set, evidence) for c in checks]
    findings.sort(
        key=lambda f: (
            _STATUS_PRIORITY.get(f.status, 99),
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                f.severity.value, 9
            ),
            f.check_id,
        )
    )

    live_pending = [f.check_id for f in findings if f.status == FindingStatus.SKIPPED]
    if scan_mode == "live" and live_pending:
        warnings.append(
            "Some configuration checks are not implemented yet and were marked "
            f"pending: {', '.join(sorted(live_pending))}."
        )

    return ScanResult(
        version=__version__,
        tenant_id=tenant_id,
        tenant_display_name=tenant_display_name,
        scan_mode=scan_mode,
        auth_mode=auth.mode.value,
        scanned_at=datetime.now(UTC).isoformat(),
        owned_capabilities=owned,
        capability_summaries=summaries,
        subscribed_skus=skus,
        findings=findings,
        recommended_next_steps=_recommended_next_steps(findings),
        warnings=warnings,
    )
