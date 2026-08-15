"""Typed evaluator registrations for identity_ca_coverage."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.identity_ca_coverage import (
    evaluate_ca_device_code_block,
    evaluate_ca_legacy_auth_block,
    evaluate_ca_managed_devices,
    evaluate_ca_mfa_all_users,
    evaluate_ca_mfa_registration_managed,
    evaluate_ca_phishing_resistant_all,
    evaluate_ca_phishing_resistant_privileged,
)
from licenselens.schema_contracts import EvaluationMode


def register_identity_ca_coverage(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.identity_ca_coverage")
    try:
        catalog.add_evaluator(
            check_id="id-ca-device-code-block",
            evaluate=evaluate_ca_device_code_block,
            input_models=(
                "ca_policies",
                "break_glass_principal_ids",
            ),
            collector_id="graph_ca",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-ca-legacy-auth-block",
            evaluate=evaluate_ca_legacy_auth_block,
            input_models=(
                "ca_policies",
                "break_glass_principal_ids",
            ),
            collector_id="graph_ca",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-ca-managed-devices",
            evaluate=evaluate_ca_managed_devices,
            input_models=(
                "ca_policies",
                "break_glass_principal_ids",
            ),
            collector_id="graph_ca",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-ca-mfa-all-users",
            evaluate=evaluate_ca_mfa_all_users,
            input_models=(
                "ca_policies",
                "break_glass_principal_ids",
            ),
            collector_id="graph_ca",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-ca-mfa-registration-managed",
            evaluate=evaluate_ca_mfa_registration_managed,
            input_models=(
                "ca_policies",
                "break_glass_principal_ids",
            ),
            collector_id="graph_ca",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-ca-phishing-resistant-all",
            evaluate=evaluate_ca_phishing_resistant_all,
            input_models=(
                "ca_policies",
                "break_glass_principal_ids",
            ),
            collector_id="graph_ca",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-ca-phishing-resistant-privileged",
            evaluate=evaluate_ca_phishing_resistant_privileged,
            input_models=(
                "ca_policies",
                "break_glass_principal_ids",
            ),
            collector_id="graph_ca",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.identity_ca_coverage")
