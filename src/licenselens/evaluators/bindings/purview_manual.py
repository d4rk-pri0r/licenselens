"""Typed evaluator registrations for purview_manual."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.purview_manual import (
    evaluate_pur_communication_compliance_readiness,
    evaluate_pur_ediscovery_readiness,
    evaluate_pur_insider_risk_readiness,
)
from licenselens.schema_contracts import EvaluationMode


def register_purview_manual(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.purview_manual")
    try:
        catalog.add_evaluator(
            check_id="pur-communication-compliance-readiness",
            evaluate=evaluate_pur_communication_compliance_readiness,
            input_models=("break_glass_principal_ids",),
            collector_id="manual_identity",
            evaluation_mode=EvaluationMode.MANUAL,
        )
        catalog.add_evaluator(
            check_id="pur-ediscovery-readiness",
            evaluate=evaluate_pur_ediscovery_readiness,
            input_models=("break_glass_principal_ids",),
            collector_id="manual_identity",
            evaluation_mode=EvaluationMode.MANUAL,
        )
        catalog.add_evaluator(
            check_id="pur-insider-risk-readiness",
            evaluate=evaluate_pur_insider_risk_readiness,
            input_models=("break_glass_principal_ids",),
            collector_id="manual_identity",
            evaluation_mode=EvaluationMode.MANUAL,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.purview_manual")
