"""Friendly display-name mapping: known-name resolution and fallback formatting."""

from __future__ import annotations

import pytest
import yaml

from licenselens.collectors.skus import demo_skus
from licenselens.friendly_names import friendly_plan_name, friendly_sku_name
from licenselens.paths import catalog_dir


@pytest.mark.parametrize(
    ("raw", "friendly"),
    [
        ("SPE_E5", "Microsoft 365 E5"),
        ("SPE_E3", "Microsoft 365 E3"),
        ("AAD_PREMIUM_P2", "Microsoft Entra ID P2"),
        ("AAD_PREMIUM", "Microsoft Entra ID P1"),
        ("MICROSOFT_SENTINEL", "Microsoft Sentinel"),
        ("AZURE_SENTINEL", "Microsoft Sentinel"),
        ("ATP_ENTERPRISE", "Microsoft Defender for Office 365 P1"),
        ("DEFENDER_ENDPOINT_P2", "Microsoft Defender for Endpoint P2"),
        ("ENTERPRISEPREMIUM", "Office 365 E5"),
        ("EMSPREMIUM", "Enterprise Mobility + Security E5"),
        ("TEAMS_EXPLORATORY", "Microsoft Teams Exploratory"),
        ("WORKLOAD_IDENTITIES_P2", "Microsoft Entra Workload ID Premium"),
    ],
)
def test_known_sku_names_resolve(raw: str, friendly: str) -> None:
    assert friendly_sku_name(raw) == friendly
    assert friendly_sku_name(raw.lower()) == friendly, "lookup must be case-insensitive"


@pytest.mark.parametrize(
    ("raw", "friendly"),
    [
        ("AAD_PREMIUM_P2", "Microsoft Entra ID P2"),
        ("MFA_PREMIUM", "Microsoft Entra ID Multifactor Authentication"),
        ("ADALLOM_S_O365", "Microsoft Defender for Cloud Apps"),
        ("EQUIVIO_ANALYTICS", "Microsoft 365 Advanced eDiscovery"),
        ("EXCHANGE_ANALYTICS", "Microsoft 365 Advanced eDiscovery"),
        ("LOCKBOX_ENTERPRISE", "Microsoft 365 Customer Lockbox"),
        ("MIP_S_CLP2", "Microsoft Purview Information Protection P2"),
        ("MIP_S_CLP1", "Microsoft Purview Information Protection P1"),
        ("THREAT_INTELLIGENCE", "Microsoft Defender for Office 365 (Threat Intelligence)"),
        ("DEFENDER_ENDPOINT_P2", "Microsoft Defender for Endpoint P2"),
        ("EXCHANGE_S_ENTERPRISE", "Exchange Online (Plan 2)"),
        ("EXCHANGE_S_STANDARD", "Exchange Online (Plan 1)"),
        ("EXCHANGESTANDARD", "Exchange Online Standard"),
        ("EOP_ENTERPRISE", "Exchange Online Protection"),
        ("BI_AZURE_P2", "Power BI Pro"),
        ("POWER_BI_PRO", "Power BI Pro"),
        ("TEAMS1", "Microsoft Teams"),
        ("MCOSTANDARD", "Microsoft 365 Phone System"),
        ("WINDEFATP", "Microsoft Defender for Endpoint"),
        ("MDM_SALES_COLLABORATION", "Microsoft Intune"),
        ("INTUNE_A", "Microsoft Intune Plan 1"),
        ("RECORDS_MANAGEMENT", "Microsoft Purview Records Management"),
        ("INSIDER_RISK_MANAGEMENT", "Microsoft Purview Insider Risk Management"),
        ("Entra_Identity_Governance", "Microsoft Entra ID Governance"),
    ],
)
def test_known_plan_names_resolve(raw: str, friendly: str) -> None:
    assert friendly_plan_name(raw) == friendly


def test_fallback_titles_unknown_names() -> None:
    assert friendly_sku_name("MY_COOL_SKU") == "My Cool SKU"
    assert friendly_plan_name("EXCHANGE_ONLINE_P2") == "Exchange Online P2"
    assert friendly_plan_name("O365_SOMETHING_NEW") == "Microsoft 365 Something New"


def test_fallback_acronym_pairs() -> None:
    assert friendly_plan_name("PBI_PRO") == "Power BI Pro"
    assert friendly_plan_name("FLOW_O365_X") == "Power Apps Microsoft 365 X"
    assert friendly_plan_name("BI_AZURE_EXTRA") == "Power BI Extra"
    assert friendly_plan_name("EOP_P2") == "Exchange Online Protection P2"


def test_fallback_preserves_already_friendly_names() -> None:
    assert friendly_sku_name("Microsoft 365 E5") == "Microsoft 365 E5"
    assert friendly_plan_name("") == ""
    assert friendly_plan_name("   ") == ""


def test_every_catalog_and_demo_name_resolves_without_raw_underscores() -> None:
    raw = yaml.safe_load((catalog_dir() / "capabilities.yaml").read_text(encoding="utf-8"))
    sku_names: set[str] = set()
    plan_names: set[str] = set()
    for capability in raw["capabilities"]:
        sku_names |= {str(n) for n in capability.get("sku_part_numbers") or []}
        sku_names |= {str(n) for n in capability.get("sku_aliases") or []}
        plan_names |= {str(n) for n in capability.get("service_plan_names") or []}
        plan_names |= {str(n) for n in capability.get("service_plan_aliases") or []}
    for sku in demo_skus():
        sku_names.add(sku.sku_part_number)
        plan_names |= {plan.service_plan_name for plan in sku.service_plans}

    for name in sorted(sku_names):
        friendly = friendly_sku_name(name)
        assert "_" not in friendly, f"SKU {name!r} renders raw underscore text: {friendly!r}"
    for name in sorted(plan_names):
        friendly = friendly_plan_name(name)
        assert "_" not in friendly, f"plan {name!r} renders raw underscore text: {friendly!r}"
