"""Typed evaluator registrations for defender."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.engine.registry import Backend
from licenselens.evaluators.defender import (
    evaluate_mdi_sensors,
)
from licenselens.schema_contracts import EvaluationMode


def register_defender(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.defender")
    try:
        catalog.add_evaluator(
            check_id="mdi-sensors-missing",
            evaluate=evaluate_mdi_sensors,
            input_models=("secure_score_controls",),
            collector_id="mdi_sensors",
            evaluation_mode=EvaluationMode.PROXY,
            backend=Backend.PROXY,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.defender")
