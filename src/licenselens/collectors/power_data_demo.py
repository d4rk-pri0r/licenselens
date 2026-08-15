"""Dry-run evidence builder for Power Platform / Power BI / Purview collection."""

from __future__ import annotations

from licenselens.collectors.power_data_fixtures import (
    DEMO_FIXTURES,
    DEMO_PBI_MODULE_DRIFT_PAYLOAD,
    DEMO_PBI_TENANT_PAYLOAD,
    DEMO_PP_DLP_PAYLOAD,
    DEMO_PP_ENVIRONMENTS_PAYLOAD,
    DEMO_PP_ISOLATION_PAYLOAD,
    DEMO_PP_TENANT_PAYLOAD,
    DEMO_PURVIEW_ABSENT_DLP_PAYLOAD,
    DEMO_PURVIEW_PAYLOAD,
)
from licenselens.collectors.power_data_models import PowerDataBundle
from licenselens.collectors.power_data_normalize import normalize_adapter_payload
from licenselens.schema_contracts import JsonValue

__all__ = [
    "DEMO_FIXTURES",
    "DEMO_PBI_MODULE_DRIFT_PAYLOAD",
    "DEMO_PBI_TENANT_PAYLOAD",
    "DEMO_PP_DLP_PAYLOAD",
    "DEMO_PP_ENVIRONMENTS_PAYLOAD",
    "DEMO_PP_ISOLATION_PAYLOAD",
    "DEMO_PP_TENANT_PAYLOAD",
    "DEMO_PURVIEW_ABSENT_DLP_PAYLOAD",
    "DEMO_PURVIEW_PAYLOAD",
    "demo_power_data_evidence",
]


def demo_power_data_evidence() -> dict[str, JsonValue]:
    """Dry-run evidence with multi-environment power-data fixtures (no live modules)."""
    adapters = {
        name: normalize_adapter_payload(payload, adapter=name)
        for name, payload in DEMO_FIXTURES.items()
    }
    bundle = PowerDataBundle(adapters=adapters, direct=True, proxy=False)
    return {
        "power_data_bundle": bundle.model_dump(mode="json"),
        "power_data_direct": True,
        "power_data_proxy": False,
        "source": "powershell.power_data",
        "proxy": False,
    }
