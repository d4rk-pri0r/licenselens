"""Typed evaluator registrations for collaboration_teams_meeting."""
from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.collaboration_teams_meeting import (
    evaluate_teams_anonymous_lobby,
    evaluate_teams_anonymous_start_disabled,
    evaluate_teams_broadcast_not_always_record,
    evaluate_teams_dialin_lobby,
    evaluate_teams_external_control_disabled,
    evaluate_teams_internal_auto_admit,
    evaluate_teams_recording_disabled,
)
from licenselens.schema_contracts import EvaluationMode


def register_collaboration_teams_meeting(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.collaboration_teams_meeting")
    try:
        catalog.add_evaluator(
            check_id="teams-anonymous-lobby",
            evaluate=evaluate_teams_anonymous_lobby,
            input_models=('collaboration_bundle',),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="teams-anonymous-start-disabled",
            evaluate=evaluate_teams_anonymous_start_disabled,
            input_models=('collaboration_bundle',),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="teams-broadcast-not-always-record",
            evaluate=evaluate_teams_broadcast_not_always_record,
            input_models=('collaboration_bundle',),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="teams-dialin-lobby",
            evaluate=evaluate_teams_dialin_lobby,
            input_models=('collaboration_bundle',),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="teams-external-control-disabled",
            evaluate=evaluate_teams_external_control_disabled,
            input_models=('collaboration_bundle',),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="teams-internal-auto-admit",
            evaluate=evaluate_teams_internal_auto_admit,
            input_models=('collaboration_bundle',),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="teams-recording-disabled",
            evaluate=evaluate_teams_recording_disabled,
            input_models=('collaboration_bundle',),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.collaboration_teams_meeting")

