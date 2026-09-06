"""Typed evaluator registrations for protective-plan assignment."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.identity_assignment import evaluate_protective_plan_assignment
from licenselens.schema_contracts import EvaluationMode


def register_identity_assignment(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.identity_assignment")
    try:
        catalog.add_evaluator(
            check_id="id-protective-plan-assignment",
            evaluate=evaluate_protective_plan_assignment,
            input_models=("license_assignment",),
            collector_id="license_assignment_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.identity_assignment")
