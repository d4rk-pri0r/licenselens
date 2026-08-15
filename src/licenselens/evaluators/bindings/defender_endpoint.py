"""Typed evaluator registrations for defender_endpoint."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.defender_endpoint import (
    evaluate_mde_onboard_gap,
)
from licenselens.schema_contracts import EvaluationMode


def register_defender_endpoint(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.defender_endpoint")
    try:
        catalog.add_evaluator(
            check_id="mde-onboard-gap",
            evaluate=evaluate_mde_onboard_gap,
            input_models=("mde_summary",),
            collector_id="mde_onboarding",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.defender_endpoint")
