"""Deterministic, frozen ``ScanResult`` fixtures for HTML report render-contract tests.

These builders materialize every enumerated variant of the report's status,
exposure, and capability-outcome domains so the render-contract tests in
``test_report_render.py`` can assert against a single, reproducible input.

Determinism contract: no wall-clock, no randomness, no filesystem or network
access. Every value is a fixed literal or derived from a fixed literal, so two
runs produce byte-identical models.
"""

from __future__ import annotations

from licenselens.models import (
    CAPABILITY_STATUS_LABELS,
    STATUS_PLAIN_LABELS,
    BlastRadius,
    CapabilityOutcome,
    CapabilityRollup,
    CapabilitySummary,
    CheckPack,
    Confidence,
    Effort,
    ExposureClass,
    Finding,
    FindingStatus,
    ScanResult,
    ServicePlan,
    Severity,
    SubscribedSku,
    TopMove,
    ValueImpact,
    Workload,
)

# Fixed timestamp — no wall-clock anywhere in these fixtures.
SCANNED_AT = "2026-01-15T09:30:00+00:00"
VERSION = "0.3.0"

# Prompt-injection payload reused verbatim in warnings and the tenant name.
MALICIOUS = "<script>alert(1)</script>"

# Long unbroken strings (>=120 chars, no spaces) to stress layout/token wrapping.
LONG_TENANT_ID = "tenant-" + "a" * 120
LONG_TENANT_SLUG = "slug-" + "b" * 120
LONG_SKU_PART_NUMBER = "sku-" + "c" * 120
LONG_SERVICE_PLAN_NAME = "plan-" + "d" * 120

# Static Microsoft admin deep link — the only external URL allowed in the output.
DEEP_LINK = "https://admin.microsoft.com/#/Security"


def _finding(
    check_id: str,
    title: str,
    status: FindingStatus,
    exposure_class: ExposureClass,
    workload: Workload,
) -> Finding:
    """Build one ``Finding`` with the given status/exposure, using fixed filler text."""
    return Finding(
        check_id=check_id,
        title=title,
        workload=workload,
        status=status,
        severity=Severity.HIGH,
        value_impact=ValueImpact.HIGH,
        impact=ValueImpact.HIGH,
        effort=Effort.HOURS,
        blast_radius=BlastRadius.ALL_USERS,
        pack=CheckPack.IDENTITY,
        exposure_class=exposure_class,
        deep_link=DEEP_LINK,
        summary=f"{check_id}: {status.value} observed.",
        customer_title=title,
        customer_summary="Plain-English summary for a busy admin.",
        customer_next_step="A concrete next step to hand to IT.",
        status_label=STATUS_PLAIN_LABELS[status.value],
        confidence=Confidence.MEDIUM,
        confidence_label="Medium confidence",
        data_sources=["microsoft.graph"],
        limitations=["First limitation", "Second limitation"],
    )


def _capability(
    cap_id: str,
    name: str,
    plain_name: str,
    status: str,
    related_check_ids: list[str],
) -> tuple[CapabilitySummary, CapabilityOutcome]:
    """Build a capability summary + matching outcome (the report joins them by id)."""
    summary = CapabilitySummary(
        id=cap_id,
        name=name,
        plain_name=plain_name,
        matched_skus=["Microsoft 365 E5"],
        matched_service_plans=["AAD_PREMIUM_P2"],
        outcome=f"What {plain_name} does for you.",
        why_it_matters=f"Why {plain_name} matters.",
        if_unused=f"What happens if {plain_name} stays off.",
        docs_url=None,
    )
    outcome = CapabilityOutcome(
        id=cap_id,
        name=name,
        plain_name=plain_name,
        status=status,
        status_label=CAPABILITY_STATUS_LABELS[status],
        related_check_ids=related_check_ids,
    )
    return summary, outcome


def comprehensive_report() -> ScanResult:
    """A report covering every status, exposure class, and capability outcome.

    * Finding statuses: gap / partial / ok / not_licensed / skipped / error.
    * Exposure classes: exposed / elevated / none, with ``has_exposed=True`` and a
      matching ``exposed_check_ids``.
    * Capability outcomes: fully_working / needs_attention / partly_set_up /
      not_licensed, one summary per outcome.
    * Three ``TopMove``s, metacharacter-bearing warnings, long unbroken
      tenant/SKU/service-plan strings, and a tenant name carrying the same
      malicious payload as the warnings.
    """
    findings = [
        _finding(
            "id-ca-priv-gaps",
            "Conditional Access MFA is not enforced",
            FindingStatus.GAP,
            ExposureClass.EXPOSED,
            Workload.IDENTITY,
        ),
        _finding(
            "mde-onboard-gap",
            "Defender for Endpoint is not onboarded",
            FindingStatus.PARTIAL,
            ExposureClass.ELEVATED,
            Workload.ENDPOINT,
        ),
        _finding(
            "id-security-defaults-on",
            "Security defaults are enabled",
            FindingStatus.OK,
            ExposureClass.NONE,
            Workload.IDENTITY,
        ),
        _finding(
            "sen-ueba-not-enabled",
            "Sentinel UEBA is not licensed",
            FindingStatus.NOT_LICENSED,
            ExposureClass.NONE,
            Workload.SENTINEL,
        ),
        _finding(
            "mdo-p2-policies-default",
            "Email protection policies could not be checked",
            FindingStatus.SKIPPED,
            ExposureClass.NONE,
            Workload.DEFENDER,
        ),
        _finding(
            "pur-dlp-not-enforced",
            "Data loss prevention could not be verified",
            FindingStatus.ERROR,
            ExposureClass.NONE,
            Workload.PURVIEW,
        ),
    ]

    capabilities = [
        _capability(
            "conditional_access",
            "Conditional Access",
            "Conditional Access",
            "needs_attention",
            ["id-ca-priv-gaps"],
        ),
        _capability(
            "identity_protection",
            "Entra ID Protection",
            "Identity Protection",
            "fully_working",
            ["id-security-defaults-on"],
        ),
        _capability(
            "endpoint_protection",
            "Defender for Endpoint",
            "Endpoint Detection & Response",
            "partly_set_up",
            ["mde-onboard-gap"],
        ),
        # Included purely to exercise the not_licensed capability-card variant.
        _capability(
            "sentinel_ueba",
            "Sentinel UEBA",
            "User & Entity Behavior Analytics",
            "not_licensed",
            ["sen-ueba-not-enabled"],
        ),
    ]

    warnings = [
        MALICIOUS,
        "Ampersand & less-than < and greater-than > appear here.",
        "Single 'quotes' and \"double quotes\" appear here.",
    ]

    moves = [
        TopMove(
            title="Turn on MFA for every account",
            why="MFA blocks the vast majority of account-takeover attacks.",
            effort=Effort.HOURS,
            check_ids=["id-ca-priv-gaps"],
            deep_link=DEEP_LINK,
            customer_next_step="Create a Conditional Access policy that requires MFA.",
        ),
        TopMove(
            title="Onboard devices to Defender for Endpoint",
            why="EDR gives you visibility into every managed endpoint.",
            effort=Effort.HALF_DAY,
            check_ids=["mde-onboard-gap"],
            deep_link=DEEP_LINK,
            customer_next_step="Turn on auto-onboarding in the endpoint portal.",
        ),
        TopMove(
            title="Review dormant privileged accounts",
            why="Dormant admins are a standing breach vector.",
            effort=Effort.HOURS,
            check_ids=["id-dormant-privileged"],
            deep_link=None,
            customer_next_step="Run the privileged users report and revoke unused roles.",
        ),
    ]

    skus = [
        SubscribedSku(
            sku_id=None,
            sku_part_number=LONG_SKU_PART_NUMBER,
            capability_status="Enabled",
            prepaid_units=300,
            consumed_units=300,
            service_plans=[
                ServicePlan(
                    service_plan_id=None,
                    service_plan_name=LONG_SERVICE_PLAN_NAME,
                    provisioning_status="Success",
                ),
            ],
        ),
    ]

    return ScanResult(
        version=VERSION,
        tenant_id=LONG_TENANT_ID,
        tenant_display_name=f"Contoso {MALICIOUS}",
        tenant_slug=LONG_TENANT_SLUG,
        scan_mode="dry_run",
        auth_mode=None,
        scanned_at=SCANNED_AT,
        owned_capabilities=["conditional_access", "identity_protection", "endpoint_protection"],
        capability_summaries=[s for s, _ in capabilities],
        subscribed_skus=skus,
        findings=findings,
        recommended_next_steps=["Enable MFA", "Onboard endpoints"],
        warnings=warnings,
        limitations=["Findings are advisory, not a compliance certification."],
        data_sources_used=["microsoft.graph"],
        workspace_resource_id=None,
        strict_proxy=True,
        packs_scanned=["identity", "endpoint"],
        moves=moves,
        capability_rollup=CapabilityRollup(
            you_own=3,
            fully_working=1,
            needs_attention=1,
            partly_set_up=1,
            not_licensed=1,
            realized_percent=33,
        ),
        capability_outcomes=[o for _, o in capabilities],
        has_exposed=True,
        exposed_check_ids=["id-ca-priv-gaps"],
    )


def empty_report() -> ScanResult:
    """A report with no findings, capabilities, outcomes, or moves.

    ``capability_rollup`` is all-zero, ``realized_percent`` is 0, ``has_exposed``
    is False, and no ``TopMove``s are present.
    """
    return ScanResult(
        version=VERSION,
        tenant_id=None,
        tenant_display_name=None,
        tenant_slug=None,
        scan_mode="dry_run",
        auth_mode=None,
        scanned_at=SCANNED_AT,
        owned_capabilities=[],
        capability_summaries=[],
        subscribed_skus=[],
        findings=[],
        recommended_next_steps=[],
        warnings=[],
        limitations=[],
        data_sources_used=[],
        workspace_resource_id=None,
        strict_proxy=True,
        packs_scanned=[],
        moves=[],
        capability_rollup=CapabilityRollup(),
        capability_outcomes=[],
        has_exposed=False,
        exposed_check_ids=[],
    )
