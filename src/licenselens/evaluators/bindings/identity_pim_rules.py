"""Typed evaluator registrations for identity_pim_rules."""
from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.identity_pim_rules import (
    evaluate_pim_ga_activation_alert,
    evaluate_pim_ga_activation_approval,
    evaluate_pim_no_outside_pam,
    evaluate_pim_no_permanent_privileged,
    evaluate_pim_other_activation_alert,
    evaluate_pim_privileged_assignment_alert,
)
from licenselens.schema_contracts import EvaluationMode


def register_identity_pim_rules(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.identity_pim_rules")
    try:
        catalog.add_evaluator(
            check_id="id-pim-ga-activation-alert",
            evaluate=evaluate_pim_ga_activation_alert,
            input_models=('pim_policies_bundle',),
            collector_id="graph_pim_policies",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-pim-ga-activation-approval",
            evaluate=evaluate_pim_ga_activation_approval,
            input_models=('pim_policies_bundle',),
            collector_id="graph_pim_policies",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-pim-no-outside-pam",
            evaluate=evaluate_pim_no_outside_pam,
            input_models=('role_assignments', 'role_eligibilities',),
            collector_id="graph_pim",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-pim-no-permanent-privileged",
            evaluate=evaluate_pim_no_permanent_privileged,
            input_models=('role_assignments', 'role_eligibilities',),
            collector_id="graph_pim",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-pim-other-activation-alert",
            evaluate=evaluate_pim_other_activation_alert,
            input_models=('pim_policies_bundle',),
            collector_id="graph_pim_policies",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-pim-privileged-assignment-alert",
            evaluate=evaluate_pim_privileged_assignment_alert,
            input_models=('pim_policies_bundle',),
            collector_id="graph_pim_policies",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.identity_pim_rules")

