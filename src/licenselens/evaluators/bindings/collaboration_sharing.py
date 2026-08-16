"""Typed evaluator registrations for collaboration_sharing."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.collaboration_sharing import (
    evaluate_spo_domain_restrictions,
    evaluate_spo_onedrive_sharing_limited,
    evaluate_spo_sharing_capability_limited,
    evaluate_spo_unmanaged_device_access,
)
from licenselens.schema_contracts import EvaluationMode


def register_collaboration_sharing(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.collaboration_sharing")
    try:
        catalog.add_evaluator(
            check_id="spo-domain-restrictions",
            evaluate=evaluate_spo_domain_restrictions,
            input_models=("collaboration_bundle",),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="spo-onedrive-sharing-limited",
            evaluate=evaluate_spo_onedrive_sharing_limited,
            input_models=("collaboration_bundle",),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="spo-sharing-capability-limited",
            evaluate=evaluate_spo_sharing_capability_limited,
            input_models=("collaboration_bundle",),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="spo-unmanaged-device-access",
            evaluate=evaluate_spo_unmanaged_device_access,
            input_models=("collaboration_bundle",),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.collaboration_sharing")
