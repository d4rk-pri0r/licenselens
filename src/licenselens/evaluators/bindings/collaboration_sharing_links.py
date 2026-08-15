"""Typed evaluator registrations for collaboration_sharing_links."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.collaboration_sharing_links import (
    evaluate_spo_anyone_link_expiration,
    evaluate_spo_anyone_link_view,
    evaluate_spo_default_link_specific,
    evaluate_spo_default_link_view,
    evaluate_spo_verification_reauth,
)
from licenselens.schema_contracts import EvaluationMode


def register_collaboration_sharing_links(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.collaboration_sharing_links")
    try:
        catalog.add_evaluator(
            check_id="spo-anyone-link-expiration",
            evaluate=evaluate_spo_anyone_link_expiration,
            input_models=("collaboration_bundle",),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="spo-anyone-link-view",
            evaluate=evaluate_spo_anyone_link_view,
            input_models=("collaboration_bundle",),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="spo-default-link-specific",
            evaluate=evaluate_spo_default_link_specific,
            input_models=("collaboration_bundle",),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="spo-default-link-view",
            evaluate=evaluate_spo_default_link_view,
            input_models=("collaboration_bundle",),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="spo-verification-reauth",
            evaluate=evaluate_spo_verification_reauth,
            input_models=("collaboration_bundle",),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.collaboration_sharing_links")
