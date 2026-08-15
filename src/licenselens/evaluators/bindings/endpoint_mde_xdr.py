"""Typed evaluator registrations for endpoint_mde_xdr."""
from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.endpoint_mde_xdr import (
    evaluate_mde_sensor_health,
    evaluate_xdr_incident_readiness,
)
from licenselens.schema_contracts import EvaluationMode


def register_endpoint_mde_xdr(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.endpoint_mde_xdr")
    try:
        catalog.add_evaluator(
            check_id="mde-sensor-health",
            evaluate=evaluate_mde_sensor_health,
            input_models=('mde_health',),
            collector_id="mde_health_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="xdr-incident-readiness",
            evaluate=evaluate_xdr_incident_readiness,
            input_models=('security_alerts_bundle',),
            collector_id="security_alerts_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.endpoint_mde_xdr")

