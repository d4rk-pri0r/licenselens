"""Typed evaluator registrations for endpoint_intune."""
from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.endpoint_intune import (
    evaluate_endpoint_compliance_noncompliance_action,
    evaluate_endpoint_compliance_policy_assigned,
    evaluate_endpoint_enrollment_coverage,
)
from licenselens.schema_contracts import EvaluationMode


def register_endpoint_intune(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.endpoint_intune")
    try:
        catalog.add_evaluator(
            check_id="endpoint-compliance-noncompliance-action",
            evaluate=evaluate_endpoint_compliance_noncompliance_action,
            input_models=('intune_bundle',),
            collector_id="intune_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="endpoint-compliance-policy-assigned",
            evaluate=evaluate_endpoint_compliance_policy_assigned,
            input_models=('intune_bundle',),
            collector_id="intune_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="endpoint-enrollment-coverage",
            evaluate=evaluate_endpoint_enrollment_coverage,
            input_models=('intune_bundle',),
            collector_id="intune_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.endpoint_intune")

