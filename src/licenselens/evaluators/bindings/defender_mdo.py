"""Typed evaluator registrations for defender_mdo."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.engine.registry import Backend
from licenselens.evaluators.defender_mdo import (
    evaluate_mdo_p2_policies,
)
from licenselens.evaluators.defender_mdo_forward import (
    evaluate_mdo_mailbox_intelligence,
    evaluate_mdo_outbound_spam_forwarding_block,
    evaluate_mdo_transport_rule_external_forward,
)
from licenselens.schema_contracts import EvaluationMode


def register_defender_mdo(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.defender_mdo")
    try:
        catalog.add_evaluator(
            check_id="mdo-p2-policies-default",
            evaluate=evaluate_mdo_p2_policies,
            input_models=("secure_score_controls",),
            collector_id="graph_mdo",
            evaluation_mode=EvaluationMode.DIRECT_WITH_PROXY_FALLBACK,
            backend=Backend.PROXY,
        )
        catalog.add_evaluator(
            check_id="mdo-outbound-spam-forwarding-block",
            evaluate=evaluate_mdo_outbound_spam_forwarding_block,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="mdo-mailbox-intelligence",
            evaluate=evaluate_mdo_mailbox_intelligence,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="mdo-transport-rule-external-forward",
            evaluate=evaluate_mdo_transport_rule_external_forward,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.defender_mdo")
