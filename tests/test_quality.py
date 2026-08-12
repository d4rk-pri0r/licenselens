"""Tests for quality policy — proxy classification and evidence awareness."""

from licenselens.engine.quality import apply_quality_policy
from licenselens.models import (
    PROXY_VERIFY_NOTE,
    CheckPack,
    Confidence,
    Finding,
    FindingStatus,
    Severity,
    ValueImpact,
    Workload,
)


def _make_finding(
    check_id: str,
    *,
    evidence: dict | None = None,
    data_sources: list[str] | None = None,
    status: FindingStatus = FindingStatus.PARTIAL,
) -> Finding:
    """Minimal valid Finding for quality-policy tests."""
    return Finding(
        check_id=check_id,
        title=check_id,
        workload=Workload.DEFENDER,
        status=status,
        severity=Severity.MEDIUM,
        value_impact=ValueImpact.MEDIUM,
        summary="Test summary.",
        evidence=evidence or {},
        data_sources=data_sources or [],
        limitations=[],
        pack=CheckPack.STARTER,
    )


def test_mdo_skipped_proxy_false_bypasses_proxy_scoring():
    """MDO skipped with explicit proxy:false must NOT get Secure Score / proxy treatment."""
    finding = _make_finding(
        "mdo-p2-policies-default",
        evidence={"proxy": False, "email_proxy_enabled": False, "source": "none"},
        data_sources=[],
        status=FindingStatus.SKIPPED,
    )

    result = apply_quality_policy(finding, strict_proxy=True)

    # Must NOT inject secureScore data source
    assert "secureScore.controlScores (proxy)" not in result.data_sources

    # Must NOT inject the proxy-verify limitation note
    assert PROXY_VERIFY_NOTE not in result.limitations

    # Confidence stays LOW from SKIPPED status (line 89-90), not from proxy block
    assert result.confidence == Confidence.LOW


def test_mdi_without_explicit_proxy_false_still_gets_proxy_treatment():
    """MDI check (proxy-based) without explicit proxy:false gets full proxy treatment."""
    finding = _make_finding(
        "mdi-sensors-missing",
        data_sources=[],
        status=FindingStatus.PARTIAL,
    )

    result = apply_quality_policy(finding, strict_proxy=True)

    # Should inject secureScore data source
    assert "secureScore.controlScores (proxy)" in result.data_sources

    # Should inject the proxy-verify limitation note
    assert PROXY_VERIFY_NOTE in result.limitations

    # Should be demoted to LOW confidence
    assert result.confidence == Confidence.LOW


def test_mdo_with_proxy_true_still_gets_proxy_treatment():
    """MDO with proxy:true (allow-email-proxy path) gets full proxy treatment."""
    finding = _make_finding(
        "mdo-p2-policies-default",
        evidence={"proxy": True},
        data_sources=["secureScore.controlScores"],
        status=FindingStatus.PARTIAL,
    )

    result = apply_quality_policy(finding, strict_proxy=True)

    # Already has secureScore source — should not duplicate
    assert result.data_sources.count("secureScore.controlScores (proxy)") <= 1

    # Should still inject the proxy-verify limitation note
    assert PROXY_VERIFY_NOTE in result.limitations

    # Should be LOW confidence
    assert result.confidence == Confidence.LOW


def test_proxy_check_id_with_no_evidence_proxy_key_still_proxy():
    """When evidence has no 'proxy' key at all, check_id membership still triggers proxy."""
    finding = _make_finding(
        "mdi-sensors-missing",
        evidence={},
        data_sources=[],
        status=FindingStatus.PARTIAL,
    )

    result = apply_quality_policy(finding, strict_proxy=True)

    assert "secureScore.controlScores (proxy)" in result.data_sources
    assert PROXY_VERIFY_NOTE in result.limitations
