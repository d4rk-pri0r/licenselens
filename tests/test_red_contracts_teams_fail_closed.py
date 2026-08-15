"""RED contract: unsupported Teams v2 surface must not yield OK (AF-C / MN-04)."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.collaboration_demo import demo_collaboration_evidence
from licenselens.evaluators.collaboration_teams_apps import (
    evaluate_teams_custom_apps_governed,
    evaluate_teams_microsoft_apps_governed,
    evaluate_teams_third_party_apps_governed,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus, Workload


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=Workload.COLLABORATION)


def _surface(bundle: dict[str, Any], adapter: str, surface: str) -> dict[str, Any]:
    return bundle["adapters"][adapter]["surfaces"][surface]


def _legacy_policies_all_blocked(evidence: dict[str, Any]) -> None:
    """Make legacy app permission policies look fully governed (would be OK alone)."""
    items = _surface(evidence["collaboration_bundle"], "teams_apps", "app_permission_policies")[
        "items"
    ]
    for item in items:
        props = item["properties"]
        props["DefaultCatalogAppsType"] = "BlockedAppList"
        props["GlobalCatalogAppsType"] = "BlockedAppList"
        props["PrivateCatalogAppsType"] = "BlockedAppList"


def _force_v2_unreadable(evidence: dict[str, Any]) -> None:
    v2 = _surface(evidence["collaboration_bundle"], "teams_apps", "app_settings_v2")
    v2["status"] = "unsupported"
    v2["reason"] = "v2 org-wide app settings unavailable"
    v2["items"] = []


def _assert_fail_closed(result: Any, *, label: str) -> None:
    assert result.status in {FindingStatus.PARTIAL, FindingStatus.SKIPPED}, (
        f"{label}: unsupported/unreadable Teams v2 must yield PARTIAL or SKIPPED, "
        f"got status={result.status!r} (AF-C)"
    )
    assert result.status is not FindingStatus.OK, (
        f"{label}: Teams v2 unreadable must never return OK (AF-C)"
    )
    assert result.confidence is not Confidence.HIGH, (
        f"{label}: Teams v2 unreadable must not claim high confidence, "
        f"got {result.confidence!r} (AF-C)"
    )


def test_teams_microsoft_apps_v2_unreadable_is_fail_closed() -> None:
    evidence = demo_collaboration_evidence()
    _legacy_policies_all_blocked(evidence)
    _force_v2_unreadable(evidence)

    result = evaluate_teams_microsoft_apps_governed(
        _check("teams-microsoft-apps-governed"),
        evidence,
    )
    _assert_fail_closed(result, label="teams-microsoft-apps-governed")


def test_teams_third_party_apps_v2_unreadable_is_fail_closed() -> None:
    evidence = demo_collaboration_evidence()
    _legacy_policies_all_blocked(evidence)
    _force_v2_unreadable(evidence)

    result = evaluate_teams_third_party_apps_governed(
        _check("teams-third-party-apps-governed"),
        evidence,
    )
    _assert_fail_closed(result, label="teams-third-party-apps-governed")


def test_teams_custom_apps_v2_unreadable_is_fail_closed() -> None:
    evidence = demo_collaboration_evidence()
    _legacy_policies_all_blocked(evidence)
    _force_v2_unreadable(evidence)

    result = evaluate_teams_custom_apps_governed(
        _check("teams-custom-apps-governed"),
        evidence,
    )
    _assert_fail_closed(result, label="teams-custom-apps-governed")
