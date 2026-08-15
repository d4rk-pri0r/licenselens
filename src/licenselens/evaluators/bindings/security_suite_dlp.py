"""Typed evaluator registrations for security_suite_dlp."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.security_suite_dlp import (
    evaluate_mdo_unified_audit_enabled,
    evaluate_pur_dlp_enforcement_block,
    evaluate_pur_dlp_locations_complete,
    evaluate_pur_dlp_notifications,
    evaluate_pur_dlp_policy_present,
)
from licenselens.schema_contracts import EvaluationMode


def register_security_suite_dlp(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.security_suite_dlp")
    try:
        catalog.add_evaluator(
            check_id="mdo-unified-audit-enabled",
            evaluate=evaluate_mdo_unified_audit_enabled,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="pur-dlp-enforcement-block",
            evaluate=evaluate_pur_dlp_enforcement_block,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="pur-dlp-locations-complete",
            evaluate=evaluate_pur_dlp_locations_complete,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="pur-dlp-notifications",
            evaluate=evaluate_pur_dlp_notifications,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="pur-dlp-policy-present",
            evaluate=evaluate_pur_dlp_policy_present,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.security_suite_dlp")
