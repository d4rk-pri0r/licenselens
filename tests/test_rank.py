"""Move ranking: exposed > ordinary gap, direct > proxy, stable ties, pack demotion."""

from licenselens.engine.rank import PACK_RANK, move_score, rank_moves
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
    status: FindingStatus = FindingStatus.GAP,
    *,
    impact: ValueImpact = ValueImpact.HIGH,
    effort: Effort = Effort.HOURS,
    pack: CheckPack = CheckPack.IDENTITY,
    exposure: ExposureClass = ExposureClass.NONE,
    confidence: Confidence = Confidence.HIGH,
    proxy: bool = False,
    customer_next_step: str = "",
) -> Finding:
    return Finding(
        check_id=check_id,
        title=check_id,
        workload=Workload.GENERAL,
        status=status,
        severity=Severity.HIGH,
        value_impact=impact,
        impact=impact,
        effort=effort,
        pack=pack,
        exposure_class=exposure,
        confidence=confidence,
        summary=f"{check_id}: gap",
        customer_next_step=customer_next_step or f"Turn on {check_id}.",
        data_sources=["secureScore.controlScores (proxy)"] if proxy else ["microsoft.graph"],
    )


def test_exposed_beats_ordinary_gap():
    exposed = _finding("id-a", exposure=ExposureClass.EXPOSED)
    ordinary = _finding("id-b")
    assert move_score(exposed) > move_score(ordinary)
    moves = rank_moves([ordinary, exposed])
    assert moves[0].check_ids == ["id-a"]


def test_direct_beats_proxy_at_equal_score():
    direct = _finding("id-a")
    proxy = _finding("mdo-a", pack=CheckPack.EMAIL, proxy=True)
    assert move_score(direct) > move_score(proxy)
    moves = rank_moves([proxy, direct], packs=["identity", "email"])
    assert moves[0].check_ids == ["id-a"]


def test_higher_impact_wins():
    high = _finding("id-a", impact=ValueImpact.HIGH)
    low = _finding("id-b", impact=ValueImpact.LOW)
    assert move_score(high) > move_score(low)


def test_easier_effort_wins():
    minutes = _finding("id-a", effort=Effort.MINUTES)
    days = _finding("id-b", effort=Effort.DAYS)
    assert move_score(minutes) > move_score(days)


def test_stable_tie_breaks_by_check_id():
    a = _finding("id-a")
    b = _finding("id-b")
    moves = rank_moves([b, a])
    assert [m.check_ids[0] for m in moves] == ["id-a", "id-b"]
    # Reversed input order still yields identical output.
    moves2 = rank_moves([a, b])
    assert [m.check_ids[0] for m in moves2] == ["id-a", "id-b"]


def test_pack_preference_identity_over_endpoint_over_starter():
    identity = _finding("id-a", pack=CheckPack.IDENTITY)
    endpoint = _finding("mde-a", pack=CheckPack.ENDPOINT)
    starter = _finding("pur-a", pack=CheckPack.STARTER)
    assert PACK_RANK[CheckPack.IDENTITY] < PACK_RANK[CheckPack.ENDPOINT]
    assert PACK_RANK[CheckPack.ENDPOINT] < PACK_RANK[CheckPack.STARTER]
    moves = rank_moves([starter, endpoint, identity])
    assert [m.check_ids[0] for m in moves] == ["id-a", "mde-a", "pur-a"]


def test_starter_demoted_off_default_card_when_packs_exclude_starter():
    identity = _finding("id-a", pack=CheckPack.IDENTITY)
    starter = _finding("pur-a", pack=CheckPack.STARTER)
    # Default talk packs exclude starter.
    moves = rank_moves([starter, identity], packs=["identity", "email", "endpoint"])
    assert [m.check_ids[0] for m in moves] == ["id-a"]
    # Explicit starter scope includes it.
    moves_all = rank_moves([starter, identity])
    assert len(moves_all) == 2


def test_limit_three_moves():
    findings = [_finding(f"id-{i}") for i in range(5)]
    moves = rank_moves(findings, limit=3)
    assert len(moves) == 3


def test_only_gap_and_partial_are_actionable():
    ok = _finding("id-a", status=FindingStatus.OK)
    partial = _finding("id-b", status=FindingStatus.PARTIAL)
    gap = _finding("id-c")
    moves = rank_moves([ok, partial, gap])
    assert all(m.check_ids != ["id-a"] for m in moves)
    assert {m.check_ids[0] for m in moves} == {"id-b", "id-c"}
