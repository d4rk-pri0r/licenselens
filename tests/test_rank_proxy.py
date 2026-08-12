"""Rank proxy classification must be evidence-path aware, mirroring quality.py.

quality.py's `is_proxy` respects an explicit `evidence.proxy: False` opt-out
(commit cbc4eeb); rank.py must mirror that exact pattern so the two engines
never disagree about whether a finding is a proxy finding.
"""

from licenselens.engine.rank import _is_proxy, move_score
from licenselens.models import (
    CheckPack,
    Confidence,
    Effort,
    ExposureClass,
    Finding,
    FindingStatus,
    Severity,
    ValueImpact,
    Workload,
)


def _finding(
    check_id: str,
    *,
    evidence: dict | None = None,
    data_sources: list[str] | None = None,
    pack: CheckPack = CheckPack.STARTER,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=check_id,
        workload=Workload.GENERAL,
        status=FindingStatus.GAP,
        severity=Severity.HIGH,
        value_impact=ValueImpact.HIGH,
        impact=ValueImpact.HIGH,
        effort=Effort.HOURS,
        pack=pack,
        exposure_class=ExposureClass.NONE,
        confidence=Confidence.HIGH,
        summary=f"{check_id}: gap",
        evidence=evidence if evidence is not None else {},
        data_sources=data_sources if data_sources is not None else ["microsoft.graph"],
    )


def test_mdo_skipped_finding_is_not_halved():
    """(a) MDO skipped with explicit proxy:false keeps a full (unhalved) score.

    The check_id is in PROXY_CHECK_IDS but evidence.proxy is explicitly False,
    so check-id membership alone must not classify it as a proxy finding.
    """
    mdo_skipped = _finding(
        "mdo-p2-policies-default",
        evidence={"proxy": False, "email_proxy_enabled": False, "source": "none"},
        data_sources=[],
    )
    equivalent = _finding("id-not-a-proxy-check")
    assert not _is_proxy(mdo_skipped)
    assert move_score(mdo_skipped) == move_score(equivalent)


def test_proxy_false_with_secure_score_source_matches_quality_mirror():
    """(b) With a secureScore-named data source, rank mirrors quality.py exactly.

    quality.py's data-source clause matches the bare "secureScore.controlScores"
    string regardless of evidence.proxy, so it still classifies the finding as
    proxy. rank must agree — the explicit `proxy: False` opt-out only gates the
    check-id membership clause, never the data-source clause.
    """
    finding = _finding(
        "mdo-p2-policies-default",
        evidence={"proxy": False},
        data_sources=["secureScore.controlScores"],
    )
    # Same classification as quality.py for this exact input.
    assert _is_proxy(finding) is True


def test_mdi_and_purview_proxy_findings_still_proxy():
    """(c) MDI/Purview findings without an explicit proxy opt-out stay proxy."""
    assert _is_proxy(_finding("mdi-sensors-missing"))
    assert _is_proxy(_finding("pur-dlp-not-enforced"))


def test_proxy_false_with_proxy_labeled_source_still_proxy():
    """A proxy-labeled data source still wins over `proxy: False` evidence."""
    finding = _finding(
        "mdi-sensors-missing",
        evidence={"proxy": False},
        data_sources=["secureScore.controlScores (proxy)"],
    )
    assert _is_proxy(finding)
