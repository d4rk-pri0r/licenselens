"""Typed evaluator registrations for identity_manual."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.identity_manual import (
    evaluate_ai_agents_risky_block,
    evaluate_idprotect_notify_high_risk,
    evaluate_logs_to_soc,
)
from licenselens.schema_contracts import EvaluationMode


def register_identity_manual(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.identity_manual")
    try:
        catalog.add_evaluator(
            check_id="id-ai-agents-risky-block",
            evaluate=evaluate_ai_agents_risky_block,
            input_models=("ca_policies",),
            collector_id="graph_ca",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-idprotect-notify-high-risk",
            evaluate=evaluate_idprotect_notify_high_risk,
            input_models=("break_glass_principal_ids",),
            collector_id="manual_identity",
            evaluation_mode=EvaluationMode.MANUAL,
        )
        catalog.add_evaluator(
            check_id="id-logs-to-soc",
            evaluate=evaluate_logs_to_soc,
            input_models=("break_glass_principal_ids",),
            collector_id="manual_identity",
            evaluation_mode=EvaluationMode.MANUAL,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.identity_manual")
