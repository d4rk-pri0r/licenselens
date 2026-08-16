"""Typed evaluator registrations for endpoint_intune_depth."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.endpoint_intune_depth import (
    evaluate_endpoint_asr_rules,
    evaluate_endpoint_bitlocker_policy,
    evaluate_endpoint_compliance_enforcement,
    evaluate_endpoint_mam_app_protection,
    evaluate_endpoint_tamper_protection,
)
from licenselens.schema_contracts import EvaluationMode


def register_endpoint_intune_depth(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.endpoint_intune_depth")
    try:
        catalog.add_evaluator(
            check_id="ep-asr-rules",
            evaluate=evaluate_endpoint_asr_rules,
            input_models=("intune_bundle",),
            collector_id="intune_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="ep-bitlocker-policy",
            evaluate=evaluate_endpoint_bitlocker_policy,
            input_models=("intune_bundle",),
            collector_id="intune_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="ep-tamper-protection",
            evaluate=evaluate_endpoint_tamper_protection,
            input_models=("intune_bundle",),
            collector_id="intune_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="ep-compliance-enforcement",
            evaluate=evaluate_endpoint_compliance_enforcement,
            input_models=("intune_bundle",),
            collector_id="intune_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="ep-mam-app-protection",
            evaluate=evaluate_endpoint_mam_app_protection,
            input_models=("intune_bundle",),
            collector_id="intune_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.endpoint_intune_depth")
