"""Aggregate power-data offline fixtures for collectors and tests."""

from __future__ import annotations

from typing import Final

from licenselens.collectors.power_data_fixtures_pbi import (
    DEMO_PBI_MODULE_DRIFT_PAYLOAD,
    DEMO_PBI_TENANT_PAYLOAD,
)
from licenselens.collectors.power_data_fixtures_pp import (
    DEMO_PP_DLP_PAYLOAD,
    DEMO_PP_ENVIRONMENTS_PAYLOAD,
    DEMO_PP_ISOLATION_PAYLOAD,
    DEMO_PP_TENANT_PAYLOAD,
)
from licenselens.collectors.power_data_fixtures_purview import (
    DEMO_PURVIEW_ABSENT_DLP_PAYLOAD,
    DEMO_PURVIEW_PAYLOAD,
)
from licenselens.collectors.power_data_models import (
    PBI_TENANT_ADAPTER,
    PP_DLP_ADAPTER,
    PP_ENVIRONMENTS_ADAPTER,
    PP_ISOLATION_ADAPTER,
    PP_TENANT_ADAPTER,
    PURVIEW_ADAPTER,
)
from licenselens.schema_contracts import JsonValue

DEMO_FIXTURES: Final[dict[str, dict[str, JsonValue]]] = {
    PP_TENANT_ADAPTER: DEMO_PP_TENANT_PAYLOAD,
    PP_ENVIRONMENTS_ADAPTER: DEMO_PP_ENVIRONMENTS_PAYLOAD,
    PP_DLP_ADAPTER: DEMO_PP_DLP_PAYLOAD,
    PP_ISOLATION_ADAPTER: DEMO_PP_ISOLATION_PAYLOAD,
    PBI_TENANT_ADAPTER: DEMO_PBI_TENANT_PAYLOAD,
    PURVIEW_ADAPTER: DEMO_PURVIEW_PAYLOAD,
}

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
]
