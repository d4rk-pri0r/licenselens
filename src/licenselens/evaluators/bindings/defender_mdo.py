"""Typed evaluator registrations for defender_mdo."""
from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.engine.registry import Backend
from licenselens.evaluators.defender_mdo import (
    evaluate_mdo_p2_policies,
)
from licenselens.schema_contracts import EvaluationMode


def register_defender_mdo(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.defender_mdo")
    try:
        catalog.add_evaluator(
            check_id="mdo-p2-policies-default",
            evaluate=evaluate_mdo_p2_policies,
            input_models=('secure_score_controls',),
            collector_id="graph_mdo",
            evaluation_mode=EvaluationMode.PROXY,
            backend=Backend.PROXY,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.defender_mdo")

