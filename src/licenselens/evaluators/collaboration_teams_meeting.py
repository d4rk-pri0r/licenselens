"""Teams meeting and live-event evaluators (SCuBA MS.TEAMS.1.* rows)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from licenselens.collectors.collaboration_models import PolicyItem
from licenselens.evaluators.collaboration_lib import (
    collaboration_bundle,
    direct_meta,
    items,
    prop_bool,
    prop_str,
    unavailable,
    usable,
)
from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus

_TEAMS: Final = "teams_meeting"

_WeakPredicate = Callable[[PolicyItem], bool]


def _scan_meeting(
    bundle: Any,
    surface_name: str,
    is_weak: _WeakPredicate,
) -> tuple[str, list[str], dict[str, Any]]:
    if not usable(bundle, _TEAMS, surface_name):
        return "unavailable", [], {"readable": False}
    all_items = items(bundle, _TEAMS, surface_name)
    if not all_items:
        return "empty", [], {}
    weak_names = [item.name or item.identity or "?" for item in all_items if is_weak(item)]
    observed = {item.name or item.identity or "?": item.properties for item in all_items}
    state = "gap" if weak_names else "ok"
    return state, weak_names, {"policies": observed}


def _meeting_result(
    *,
    state: str,
    weak_names: list[str],
    evidence: dict[str, Any],
    ok_summary: str,
    gap_summary: str,
    customer_ok: str,
    customer_gap: str,
    surface_name: str,
) -> Evaluation:
    if state == "unavailable":
        return unavailable(
            f"Meeting setting ({surface_name}) could not be read; treated as unresolved.",
            adapter=_TEAMS,
            surface_name=surface_name,
            customer_summary="We could not confirm the meeting policy.",
        )
    if state == "empty":
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="No meeting policies were returned; setting is unresolved.",
            evidence=evidence,
            customer_summary="Confirm meeting policies in the Teams admin center.",
            confidence=Confidence.MEDIUM,
            limitations=["No meeting policy items were collected."],
        )
    if state == "gap":
        evidence["weak_policies"] = weak_names
        return Evaluation(
            status=FindingStatus.GAP,
            summary=f"{gap_summary} ({', '.join(weak_names)}).",
            evidence=evidence,
            customer_summary=customer_gap,
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary=ok_summary,
        evidence=evidence,
        customer_summary=customer_ok,
        **direct_meta(),
    )


def _is_true(item: PolicyItem, prop_name: str) -> bool:
    return prop_bool(item, prop_name)


def evaluate_teams_external_control_disabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    state, weak, obs = _scan_meeting(
        bundle,
        "meeting_policies",
        lambda item: _is_true(item, "AllowExternalParticipantGiveRequestControl"),
    )
    return _meeting_result(
        state=state,
        weak_names=weak,
        evidence=obs,
        ok_summary="External participants cannot request control of shared content.",
        gap_summary="External participants can request control of shared content",
        customer_ok="External attendees cannot take over shared screens.",
        customer_gap="External attendees can request control. Turn this off in meeting policies.",
        surface_name="meeting_policies",
    )


def evaluate_teams_anonymous_start_disabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    state, weak, obs = _scan_meeting(
        bundle,
        "meeting_policies",
        lambda item: _is_true(item, "AllowAnonymousUsersToStartMeeting"),
    )
    return _meeting_result(
        state=state,
        weak_names=weak,
        evidence=obs,
        ok_summary="Anonymous users cannot start meetings.",
        gap_summary="Anonymous users can start meetings",
        customer_ok="Anonymous attendees cannot start meetings on their own.",
        customer_gap="Anonymous attendees can start meetings. Turn this off in meeting policies.",
        surface_name="meeting_policies",
    )


def _auto_admit_everyone(item: PolicyItem) -> bool:
    return prop_str(item, "AutoAdmittedUsers").strip().lower() == "everyone"


def evaluate_teams_anonymous_lobby(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    state, weak, obs = _scan_meeting(bundle, "meeting_policies", _auto_admit_everyone)
    return _meeting_result(
        state=state,
        weak_names=weak,
        evidence=obs,
        ok_summary="Anonymous users and dial-in callers are not auto-admitted.",
        gap_summary="Anonymous users and dial-in callers are auto-admitted",
        customer_ok="Unmanaged attendees wait in the lobby.",
        customer_gap="Unmanaged attendees skip the lobby. Require them to wait for admission.",
        surface_name="meeting_policies",
    )


def _not_in_company(item: PolicyItem) -> bool:
    return prop_str(item, "AutoAdmittedUsers").strip().lower() != "everyoneincompany"


def evaluate_teams_internal_auto_admit(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    state, weak, obs = _scan_meeting(bundle, "meeting_policies", _not_in_company)
    return _meeting_result(
        state=state,
        weak_names=weak,
        evidence=obs,
        ok_summary="Internal users are auto-admitted to meetings.",
        gap_summary="Internal users are not auto-admitted to meetings",
        customer_ok="Your team joins meetings without lobby friction.",
        customer_gap="Internal users wait in the lobby. Admit internal users automatically.",
        surface_name="meeting_policies",
    )


def evaluate_teams_dialin_lobby(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    state, weak, obs = _scan_meeting(
        bundle,
        "meeting_policies",
        lambda item: _is_true(item, "AllowPSTNUsersToBypassLobby"),
    )
    return _meeting_result(
        state=state,
        weak_names=weak,
        evidence=obs,
        ok_summary="Dial-in callers cannot bypass the meeting lobby.",
        gap_summary="Dial-in callers can bypass the meeting lobby",
        customer_ok="Dial-in callers wait in the lobby.",
        customer_gap="Dial-in callers skip the lobby. Keep them in the lobby until admitted.",
        surface_name="meeting_policies",
    )


def evaluate_teams_recording_disabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    state, weak, obs = _scan_meeting(
        bundle,
        "meeting_policies",
        lambda item: _is_true(item, "AllowCloudRecording"),
    )
    return _meeting_result(
        state=state,
        weak_names=weak,
        evidence=obs,
        ok_summary="Meeting recording is disabled.",
        gap_summary="Meeting recording is enabled",
        customer_ok="Meeting recording is off by default.",
        customer_gap="Recording is on for some users. Disable it unless explicitly required.",
        surface_name="meeting_policies",
    )


def _broadcast_always(item: PolicyItem) -> bool:
    return prop_str(item, "BroadcastRecordingMode").strip().lower() == "alwaysenabled"


def evaluate_teams_broadcast_not_always_record(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    state, weak, obs = _scan_meeting(bundle, "broadcast_policies", _broadcast_always)
    return _meeting_result(
        state=state,
        weak_names=weak,
        evidence=obs,
        ok_summary="Live events are not set to always record.",
        gap_summary="Live events are set to always record",
        customer_ok="Live event recording is at the organizer's discretion.",
        customer_gap="Live events always record. Let organizers choose or disable recording.",
        surface_name="broadcast_policies",
    )
