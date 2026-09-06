"""WS5-A: pass_criteria on flagships, evaluator_ref, banned-word guard."""

from __future__ import annotations

import re

from licenselens.auth import AuthContext, AuthMode
from licenselens.engine.loader import load_checks
from licenselens.engine.runner import run_scan
from licenselens.models import FindingStatus

BANNED = (
    "healthy",
    "complete",
    "protected",
    "covered",
    "secure",
    "effective",
    "comprehensive",
    "fully deployed",
    "sufficient",
    "compliant",
)

_WORD = re.compile(
    r"\b(" + "|".join(re.escape(word) for word in BANNED) + r")\b",
    re.IGNORECASE,
)


def test_pass_criteria_parsed_on_flagships() -> None:
    flagships = [check for check in load_checks() if check.flagship]
    assert len(flagships) == 36
    missing = [check.id for check in flagships if check.pass_criteria is None]
    assert not missing
    incomplete = [
        check.id
        for check in flagships
        if check.pass_criteria is not None
        and (not check.pass_criteria.ok or not check.pass_criteria.gap)
    ]
    assert not incomplete


def test_finding_carries_evaluator_ref_for_registered_checks() -> None:
    result = run_scan(AuthContext(mode=AuthMode.DRY_RUN), dry_run=True)
    sample = next(
        finding for finding in result.findings if finding.check_id == "id-ca-mfa-all-users"
    )
    assert sample.evaluator_ref.startswith("licenselens.evaluators.")
    assert sample.pass_criteria is not None
    assert sample.pass_criteria.ok


def test_flagship_evidence_fields_subset_on_demo() -> None:
    result = run_scan(AuthContext(mode=AuthMode.DRY_RUN), dry_run=True)
    by_id = {finding.check_id: finding for finding in result.findings}
    actionable = {FindingStatus.OK, FindingStatus.PARTIAL, FindingStatus.GAP}
    missing: list[str] = []
    for check in load_checks():
        if not check.flagship or check.pass_criteria is None:
            continue
        finding = by_id.get(check.id)
        if finding is None or finding.status not in actionable:
            continue
        leftover = set(check.pass_criteria.evidence_fields) - set(finding.evidence)
        if leftover:
            missing.append(f"{check.id}:{sorted(leftover)}")
    assert not missing, missing


def test_pass_criteria_language_avoids_banned_words() -> None:
    hits: list[str] = []
    for check in load_checks():
        if check.pass_criteria is None:
            continue
        blob = " ".join(
            [
                check.pass_criteria.ok,
                check.pass_criteria.partial,
                check.pass_criteria.gap,
                check.pass_criteria.error,
            ]
        )
        found = sorted(set(_WORD.findall(blob)))
        if found:
            hits.append(f"{check.id}:{found}")
    assert not hits, hits
