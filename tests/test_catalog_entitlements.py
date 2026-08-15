"""Entitlement resolution matrix for expanded capability catalog."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from licenselens.catalog.capability_meta import CatalogCloud, CatalogLoadError, EntitlementKind
from licenselens.catalog.loader import load_capabilities, resolve_owned_capabilities
from licenselens.models import ServicePlan, SubscribedSku

LEGACY_EIGHT = frozenset(
    {
        "entra_id_p2",
        "conditional_access",
        "identity_protection",
        "defender_office_p2",
        "defender_endpoint_p2",
        "defender_identity",
        "microsoft_sentinel",
        "purview_dlp",
    }
)

EXPANDED_IDS = frozenset(
    {
        "exchange_online",
        "exchange_online_protection",
        "defender_office_p1",
        "sharepoint_online",
        "onedrive_for_business",
        "teams",
        "power_platform",
        "power_bi_pro",
        "power_bi_premium",
        "intune",
        "defender_endpoint_p1",
        "defender_xdr",
        "purview_audit",
        "purview_sensitivity_labels",
        "purview_insider_risk",
        "purview_ediscovery",
        "purview_communication_compliance",
        "log_analytics",
        "defender_for_cloud_cspm",
        "defender_for_cloud_servers",
    }
)


def _sku(
    part: str,
    plans: list[tuple[str, str]],
    *,
    status: str = "Enabled",
) -> SubscribedSku:
    return SubscribedSku(
        sku_part_number=part,
        capability_status=status,
        service_plans=[
            ServicePlan(service_plan_name=name, provisioning_status=plan_status)
            for name, plan_status in plans
        ],
    )


def _classic_e5() -> list[SubscribedSku]:
    return [
        _sku(
            "SPE_E5",
            [
                ("AAD_PREMIUM_P2", "Success"),
                ("THREAT_INTELLIGENCE", "Success"),
                ("ATP_ENTERPRISE", "Success"),
                ("DEFENDER_ENDPOINT_P2", "Success"),
                ("MDATP_XPLAT", "Success"),
                ("ATA", "Success"),
                ("MDI_Service_Plan", "Success"),
                ("MIP_S_CLP2", "Success"),
                ("INFORMATION_BARRIERS", "Success"),
                ("EXCHANGE_S_ENTERPRISE", "Success"),
                ("EOP_ENTERPRISE", "Success"),
                ("SHAREPOINTENTERPRISE", "Success"),
                ("TEAMS1", "Success"),
                ("MCOSTANDARD", "Success"),
                ("FLOW_O365_P2", "Success"),
                ("POWERAPPS_O365_P2", "Success"),
                ("BI_AZURE_P2", "Success"),
                ("INTUNE_A", "Success"),
                ("M365_ADVANCED_AUDITING", "Success"),
                ("EQUIVIO_ANALYTICS", "Success"),
                ("INSIDER_RISK_MANAGEMENT", "Success"),
                ("COMMUNICATION_COMPLIANCE", "Success"),
            ],
        ),
        _sku("MICROSOFT_SENTINEL", [("MICROSOFT_SENTINEL", "Success")]),
    ]


def test_load_expanded_catalog_kinds_and_provenance() -> None:
    caps = load_capabilities()
    by_id = {cap.id: cap for cap in caps}
    assert LEGACY_EIGHT <= by_id.keys()
    assert EXPANDED_IDS <= by_id.keys()
    kinds = {cap.entitlement_kind for cap in caps}
    assert kinds >= {
        EntitlementKind.INCLUDED.value,
        EntitlementKind.BASE.value,
        EntitlementKind.ADD_ON.value,
        EntitlementKind.CONSUMPTION.value,
    }
    assert by_id["microsoft_sentinel"].entitlement_kind == EntitlementKind.CONSUMPTION.value
    assert by_id["defender_for_cloud_cspm"].entitlement_kind == EntitlementKind.CONSUMPTION.value
    assert by_id["power_bi_premium"].entitlement_kind == EntitlementKind.ADD_ON.value
    assert by_id["exchange_online"].entitlement_kind == EntitlementKind.BASE.value
    assert by_id["entra_id_p2"].source_version == "2026-08"
    assert "graph" in by_id["conditional_access"].backends
    assert "arm" in by_id["defender_for_cloud_servers"].backends


def test_legacy_eight_resolution_parity_on_classic_e5() -> None:
    caps = load_capabilities()
    owned = set(resolve_owned_capabilities(caps, _classic_e5()))
    assert LEGACY_EIGHT <= owned
    assert "exchange_online" in owned
    assert "teams" in owned
    assert "intune" in owned
    assert "defender_xdr" in owned
    assert "purview_audit" in owned
    assert "log_analytics" in owned


@pytest.mark.parametrize(
    ("cloud", "sku_part", "plan", "expected"),
    [
        (CatalogCloud.COMMERCIAL, "SPE_E5", "AAD_PREMIUM_P2", "entra_id_p2"),
        (CatalogCloud.GCC, "SPE_E5", "AAD_PREMIUM_P2", "entra_id_p2"),
        (CatalogCloud.GCC_HIGH, "SPE_E5_USGOV_GCCHIGH", "AAD_PREMIUM_P2", "entra_id_p2"),
        (CatalogCloud.DOD, "SPE_E5_USGOV_DOD", "AAD_PREMIUM_P2", "entra_id_p2"),
        (CatalogCloud.COMMERCIAL, "SPE_E3", "EXCHANGE_S_ENTERPRISE", "exchange_online"),
        (
            CatalogCloud.GCC_HIGH,
            "SPE_E3_USGOV_GCCHIGH",
            "SHAREPOINTENTERPRISE",
            "sharepoint_online",
        ),
        (CatalogCloud.COMMERCIAL, "POWER_BI_PRO", "BI_AZURE_P2", "power_bi_pro"),
        (CatalogCloud.COMMERCIAL, "DEFENDER_CSPM", "UNUSED_PLAN", "defender_for_cloud_cspm"),
        (CatalogCloud.DOD, "DEFENDER_SERVERS_P2", "UNUSED_PLAN", "defender_for_cloud_servers"),
        (CatalogCloud.GCC, "MICROSOFT_SENTINEL", "MICROSOFT_SENTINEL", "microsoft_sentinel"),
    ],
)
def test_cloud_sku_matrix_unlocks_expected_capability(
    cloud: CatalogCloud,
    sku_part: str,
    plan: str,
    expected: str,
) -> None:
    caps = load_capabilities()
    skus = [_sku(sku_part, [(plan, "Success")])]
    owned = resolve_owned_capabilities(caps, skus, cloud=cloud)
    assert expected in owned


def test_dod_cloud_excludes_capabilities_not_listed_for_dod() -> None:
    caps = load_capabilities()
    skus = [
        _sku(
            "SPE_E5_USGOV_DOD",
            [
                ("AAD_PREMIUM_P2", "Success"),
                ("ATA", "Success"),
                ("MDI_Service_Plan", "Success"),
                ("FLOW_O365_P2", "Success"),
            ],
        )
    ]
    owned = set(resolve_owned_capabilities(caps, skus, cloud=CatalogCloud.DOD))
    assert "entra_id_p2" in owned
    assert "defender_identity" not in owned
    assert "power_platform" not in owned


def test_unknown_sku_and_unknown_plan_never_unlock() -> None:
    caps = load_capabilities()
    skus = [
        _sku("TOTALLY_UNKNOWN_SKU_ZZZ", [("TOTALLY_UNKNOWN_PLAN_ZZZ", "Success")]),
    ]
    owned = resolve_owned_capabilities(caps, skus)
    assert owned == []


def test_disabled_plan_never_unlocks() -> None:
    caps = load_capabilities()
    skus = [
        _sku(
            "CUSTOM_SKU",
            [
                ("AAD_PREMIUM_P2", "Disabled"),
                ("THREAT_INTELLIGENCE", "Error"),
                ("DEFENDER_ENDPOINT_P2", "Pending"),
            ],
        )
    ]
    owned = resolve_owned_capabilities(caps, skus)
    assert "entra_id_p2" not in owned
    assert "defender_office_p2" not in owned
    assert "defender_endpoint_p2" not in owned


def test_disabled_sku_never_unlocks_even_with_active_plans() -> None:
    caps = load_capabilities()
    skus = [
        _sku(
            "SPE_E5",
            [("AAD_PREMIUM_P2", "Success"), ("THREAT_INTELLIGENCE", "Success")],
            status="Disabled",
        )
    ]
    owned = resolve_owned_capabilities(caps, skus)
    assert owned == []


def test_service_plan_alias_unlocks_and_ambiguous_token_does_not() -> None:
    caps = load_capabilities()
    alias_hit = resolve_owned_capabilities(
        caps,
        [_sku("FACULTY_SKU", [("AAD_PREMIUM_P2_FOR_FACULTY", "Success")])],
    )
    assert "entra_id_p2" in alias_hit
    ambiguous = resolve_owned_capabilities(
        caps,
        [_sku("FACULTY_SKU", [("AAD_PREMIUM_P2_FOR_FACULTY_EXTRA", "Success")])],
    )
    assert ambiguous == []


def test_sku_alias_unlocks_without_matching_plan() -> None:
    caps = load_capabilities()
    owned = resolve_owned_capabilities(
        caps,
        [_sku("SPE_E5_USGOV_GCCHIGH", [("SOME_OTHER_PLAN", "Success")])],
        cloud=CatalogCloud.GCC_HIGH,
    )
    assert "conditional_access" in owned
    assert "entra_id_p2" in owned


def test_duplicate_capability_id_is_collision(tmp_path: Path) -> None:
    source = Path("catalog/capabilities.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(source)
    data["capabilities"].append(
        {
            "id": "entra_id_p2",
            "name": "Duplicate",
            "workloads": ["identity"],
            "service_plan_names": ["OTHER_PLAN"],
        }
    )
    path = tmp_path / "capabilities.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(CatalogLoadError) as exc_info:
        load_capabilities(path)
    assert "duplicate_capability_id:entra_id_p2" in exc_info.value.diagnostics


def test_redundant_plan_alias_is_collision(tmp_path: Path) -> None:
    path = tmp_path / "capabilities.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "capabilities": [
                    {
                        "id": "sample",
                        "name": "Sample",
                        "workloads": ["identity"],
                        "service_plan_names": ["PLAN_A"],
                        "service_plan_aliases": ["PLAN_A"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(CatalogLoadError) as exc_info:
        load_capabilities(path)
    assert "redundant_plan_alias:sample:PLAN_A" in exc_info.value.diagnostics


def test_demo_style_e5_still_unlocks_original_security_caps() -> None:
    """Stale-state parity: original SPE_E5 + Sentinel fixture set remains stable."""
    caps = load_capabilities()
    skus = [
        _sku(
            "SPE_E5",
            [
                ("AAD_PREMIUM_P2", "Success"),
                ("MFA_PREMIUM", "Success"),
                ("ADALLOM_S_O365", "Success"),
                ("EQUIVIO_ANALYTICS", "Success"),
                ("LOCKBOX_ENTERPRISE", "Success"),
                ("MIP_S_CLP2", "Success"),
                ("THREAT_INTELLIGENCE", "Success"),
                ("DEFENDER_ENDPOINT_P2", "Success"),
            ],
        ),
        _sku("MICROSOFT_SENTINEL", [("MICROSOFT_SENTINEL", "Success")]),
    ]
    owned = set(resolve_owned_capabilities(caps, skus))
    assert {
        "entra_id_p2",
        "conditional_access",
        "identity_protection",
        "defender_office_p2",
        "defender_endpoint_p2",
        "microsoft_sentinel",
        "purview_dlp",
    } <= owned
