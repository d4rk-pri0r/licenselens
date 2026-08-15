"""Typed evaluator registrations for security_suite_spam."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.security_suite_spam import (
    evaluate_mdo_alert_policies_manual,
    evaluate_mdo_anti_spam_no_allowed_domains,
    evaluate_mdo_audit_retention_manual,
    evaluate_mdo_connection_filter_no_ip_allow,
    evaluate_mdo_connection_filter_no_safe_list,
    evaluate_mdo_safe_attachments_spo_teams,
    evaluate_mdo_spam_phish_not_inbox,
)
from licenselens.schema_contracts import EvaluationMode


def register_security_suite_spam(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.security_suite_spam")
    try:
        catalog.add_evaluator(
            check_id="mdo-alert-policies-enabled",
            evaluate=evaluate_mdo_alert_policies_manual,
            input_models=("break_glass_principal_ids",),
            collector_id="manual_identity",
            evaluation_mode=EvaluationMode.MANUAL,
        )
        catalog.add_evaluator(
            check_id="mdo-anti-spam-no-allowed-domains",
            evaluate=evaluate_mdo_anti_spam_no_allowed_domains,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="mdo-audit-retention",
            evaluate=evaluate_mdo_audit_retention_manual,
            input_models=("break_glass_principal_ids",),
            collector_id="manual_identity",
            evaluation_mode=EvaluationMode.MANUAL,
        )
        catalog.add_evaluator(
            check_id="mdo-connection-filter-no-ip-allow",
            evaluate=evaluate_mdo_connection_filter_no_ip_allow,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="mdo-connection-filter-no-safe-list",
            evaluate=evaluate_mdo_connection_filter_no_safe_list,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="mdo-safe-attachments-spo-teams",
            evaluate=evaluate_mdo_safe_attachments_spo_teams,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="mdo-spam-phish-not-inbox",
            evaluate=evaluate_mdo_spam_phish_not_inbox,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.security_suite_spam")
