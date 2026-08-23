"""Rollup rules: gap/partial/ok/proxy-cap -> YOU OWN / FULLY WORKING / % realized."""

from licenselens.engine.rollup import capability_rollup
from licenselens.models import (
    CheckDefinition,
    CheckPack,
    Finding,
    FindingStatus,
    Severity,
    ValueImpact,
    Workload,
)


def _check(check_id: str, caps: list[str], pack: CheckPack) -> CheckDefinition:
    return CheckDefinition(
        id=check_id,
        title=check_id,
        workload=Workload.GENERAL,
        required_capabilities=caps,
        pack=pack,
        impact=ValueImpact.MEDIUM,
    )


def _finding(
    check_id: str,
    status: FindingStatus,
    *,
    pack: CheckPack = CheckPack.IDENTITY,
    proxy: bool = False,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=check_id,
        workload=Workload.GENERAL,
        status=status,
        severity=Severity.HIGH,
        value_impact=ValueImpact.HIGH,
        impact=ValueImpact.HIGH,
        pack=pack,
        summary=f"{check_id}: {status.value}",
        data_sources=["secureScore.controlScores (proxy)"] if proxy else ["microsoft.graph"],
    )


def test_gap_drives_capability_to_needs_attention():
    checks = [_check("id-a", ["conditional_access"], CheckPack.IDENTITY)]
    findings = [_finding("id-a", FindingStatus.GAP)]
    rollup, outcomes = capability_rollup(checks, findings, ["conditional_access"], [], ["identity"])
    assert rollup.you_own == 1
    assert rollup.needs_attention == 1
    assert rollup.fully_working == 0
    assert rollup.realized_percent == 0
    assert outcomes[0].status == "needs_attention"


def test_all_ok_is_fully_working():
    checks = [_check("id-a", ["conditional_access"], CheckPack.IDENTITY)]
    findings = [_finding("id-a", FindingStatus.OK)]
    rollup, outcomes = capability_rollup(checks, findings, ["conditional_access"], [], ["identity"])
    assert rollup.fully_working == 1
    assert rollup.realized_percent == 100
    assert outcomes[0].status == "fully_working"


def test_proxy_cap_counts_as_partly_set_up():
    # Strict proxy caps OK -> PARTIAL, so a proxy-check capability is partly set up.
    checks = [_check("mdo-a", ["email_protection"], CheckPack.EMAIL)]
    findings = [_finding("mdo-a", FindingStatus.PARTIAL, pack=CheckPack.EMAIL, proxy=True)]
    rollup, outcomes = capability_rollup(checks, findings, ["email_protection"], [], ["email"])
    assert rollup.partly_set_up == 1
    assert rollup.fully_working == 0
    assert outcomes[0].status == "partly_set_up"


def test_error_and_skipped_are_partly_set_up():
    checks = [
        _check("id-a", ["conditional_access"], CheckPack.IDENTITY),
        _check("id-b", ["identity_protection"], CheckPack.IDENTITY),
    ]
    findings = [_finding("id-a", FindingStatus.ERROR), _finding("id-b", FindingStatus.SKIPPED)]
    rollup, _ = capability_rollup(
        checks, findings, ["conditional_access", "identity_protection"], [], ["identity"]
    )
    assert rollup.you_own == 2
    assert rollup.partly_set_up == 2
    assert rollup.fully_working == 0


def test_realized_percent_is_rounded_fraction():
    checks = [
        _check("id-a", ["conditional_access"], CheckPack.IDENTITY),
        _check("id-b", ["identity_protection"], CheckPack.IDENTITY),
        _check("id-c", ["pim"], CheckPack.IDENTITY),
        _check("id-d", ["signin_logs"], CheckPack.IDENTITY),
    ]
    findings = [
        _finding("id-a", FindingStatus.OK),
        _finding("id-b", FindingStatus.GAP),
        _finding("id-c", FindingStatus.GAP),
        _finding("id-d", FindingStatus.OK),
    ]
    rollup, _ = capability_rollup(
        checks,
        findings,
        ["conditional_access", "identity_protection", "pim", "signin_logs"],
        [],
        ["identity"],
    )
    assert rollup.you_own == 4
    assert rollup.fully_working == 2
    assert rollup.realized_percent == 50
    assert rollup.realized_sentence == "2 of 4 priority capabilities still need attention"


def test_not_licensed_capabilities_excluded_from_you_own():
    checks = [
        _check("pur-a", ["purview_dlp"], CheckPack.STARTER),
        _check("id-a", ["conditional_access"], CheckPack.IDENTITY),
    ]
    findings = [
        _finding("pur-a", FindingStatus.NOT_LICENSED, pack=CheckPack.STARTER),
        _finding("id-a", FindingStatus.OK),
    ]
    # Tenant owns only conditional_access; purview_dlp is not licensed.
    rollup, outcomes = capability_rollup(
        checks, findings, ["conditional_access"], [], ["identity", "starter"]
    )
    assert rollup.you_own == 1
    assert rollup.not_licensed == 1
    assert rollup.fully_working == 1
    assert all(o.status != "not_licensed" for o in outcomes)


def test_out_of_scope_packs_excluded_from_you_own():
    checks = [
        _check("pur-a", ["purview_dlp"], CheckPack.STARTER),
        _check("id-a", ["conditional_access"], CheckPack.IDENTITY),
    ]
    findings = [
        _finding("pur-a", FindingStatus.GAP, pack=CheckPack.STARTER),
        _finding("id-a", FindingStatus.OK),
    ]
    rollup, _ = capability_rollup(
        checks, findings, ["purview_dlp", "conditional_access"], [], ["identity"]
    )
    # Starter pack out of scope: purview capability not counted even though owned.
    assert rollup.you_own == 1
    assert rollup.fully_working == 1


def test_capability_with_no_findings_is_excluded_from_both_sides():
    """§9: missing evidence never inflates nor degrades a capability's contribution.

    A capability whose in-scope checks yielded no findings at all contributes to
    neither ``you_own`` nor ``fully_working``/``needs_attention`` — it cannot
    award credit for an unevaluated check, nor push anything toward fail.
    """
    checks = [
        _check("id-a", ["conditional_access"], CheckPack.IDENTITY),
        _check("id-b", ["identity_protection"], CheckPack.IDENTITY),
    ]
    findings = [_finding("id-a", FindingStatus.OK)]
    rollup, outcomes = capability_rollup(
        checks, findings, ["conditional_access", "identity_protection"], [], ["identity"]
    )
    assert rollup.you_own == 1
    assert rollup.fully_working == 1
    assert rollup.realized_percent == 100
    assert len(outcomes) == 1


def test_missing_evidence_never_makes_tenant_look_more_secure():
    """§9: dropping a finding cannot increase ``fully_working`` or the ratio.

    A failed/shadowed capability becomes ``partly_set_up`` (visible), never a
    clean pass; a fully-missing surface is excluded rather than credited.
    """
    checks = [
        _check("id-a", ["conditional_access"], CheckPack.IDENTITY),
        _check("id-b", ["identity_protection"], CheckPack.IDENTITY),
    ]
    baseline = [
        _finding("id-a", FindingStatus.OK),
        _finding("id-b", FindingStatus.OK),
    ]
    _, base_outcomes = capability_rollup(
        checks, baseline, ["conditional_access", "identity_protection"], [], ["identity"]
    )
    assert len(base_outcomes) == 2
    assert all(o.status == "fully_working" for o in base_outcomes)

    # Same checks, but identity_protection evidence is missing (no finding).
    shadowed = [_finding("id-a", FindingStatus.OK)]
    _, shadow_outcomes = capability_rollup(
        checks, shadowed, ["conditional_access", "identity_protection"], [], ["identity"]
    )
    assert len(shadow_outcomes) == 1
    assert shadow_outcomes[0].status == "fully_working"
    credited = [o for o in shadow_outcomes if o.id == "identity_protection"]
    assert not any(o.status == "fully_working" for o in credited)


def test_error_finding_never_counts_as_ok_or_gap():
    """§9: an error/unknown result is ``partly_set_up``, never silently pass/fail."""
    checks = [
        _check("id-a", ["conditional_access"], CheckPack.IDENTITY),
    ]
    rollup, outcomes = capability_rollup(
        checks, [_finding("id-a", FindingStatus.ERROR)], ["conditional_access"], [], ["identity"]
    )
    assert rollup.you_own == 1
    assert rollup.partly_set_up == 1
    assert rollup.fully_working == 0
    assert rollup.needs_attention == 0
    assert outcomes[0].status == "partly_set_up"
