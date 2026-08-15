"""Typed evaluator registrations for collaboration_teams_apps."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.collaboration_teams_apps import (
    evaluate_teams_custom_apps_governed,
    evaluate_teams_microsoft_apps_governed,
    evaluate_teams_third_party_apps_governed,
)
from licenselens.schema_contracts import EvaluationMode


def register_collaboration_teams_apps(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.collaboration_teams_apps")
    try:
        catalog.add_evaluator(
            check_id="teams-custom-apps-governed",
            evaluate=evaluate_teams_custom_apps_governed,
            input_models=("collaboration_bundle",),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="teams-microsoft-apps-governed",
            evaluate=evaluate_teams_microsoft_apps_governed,
            input_models=("collaboration_bundle",),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="teams-third-party-apps-governed",
            evaluate=evaluate_teams_third_party_apps_governed,
            input_models=("collaboration_bundle",),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.collaboration_teams_apps")
