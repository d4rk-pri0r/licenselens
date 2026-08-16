"""GUID-backed licensing entitlement resolution for the capability catalog.

A tenant whose subscribedSkus carry a capability's ``servicePlanId`` GUID must
unlock that capability even when the plan name is renamed or unrecognized; the
legacy name / skuPartNumber intersection remains as a backwards-compatible
fallback; and the catalog itself must stay GUID-consistent.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

from licenselens.catalog.capability_meta import CatalogLoadError
from licenselens.catalog.loader import (
    capability_summaries_for,
    load_capabilities,
    resolve_owned_capabilities,
)
from licenselens.collectors.skus import skus_from_graph_values
from licenselens.models import ServicePlan, SubscribedSku

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import validate_sku_catalog  # noqa: E402


def _entra_capability() -> tuple[object, str]:
    caps = load_capabilities()
    entra = next(c for c in caps if c.id == "entra_id_p2")
    assert entra.service_plan_ids, "entra_id_p2 must carry at least one GUID"
    return caps, entra.service_plan_ids[0]


def _sku_with_plan(
    part: str,
    plan_name: str,
    *,
    plan_id: str | None = None,
    plan_status: str = "Success",
    sku_status: str = "Enabled",
) -> SubscribedSku:
    return SubscribedSku(
        sku_part_number=part,
        capability_status=sku_status,
        service_plans=[
            ServicePlan(
                service_plan_id=plan_id,
                service_plan_name=plan_name,
                provisioning_status=plan_status,
            )
        ],
    )


def test_guid_unlocks_capability_even_with_renamed_plan_name():
    """The core acceptance: GUID present, name renamed -> capability unlocks."""
    caps, guid = _entra_capability()
    skus = [
        _sku_with_plan(
            "CUSTOM_SKU_XYZ",  # never matches any sku_part_number in the catalog
            "AAD_PREMIUM_P2_RENAMED_2026",  # not in the catalog anywhere
            plan_id=guid,
        )
    ]
    owned = resolve_owned_capabilities(caps, skus)
    # AAD_PREMIUM_P2 is a shared plan: it unlocks every capability that names it.
    assert set(owned) == {"entra_id_p2", "conditional_access", "identity_protection"}


def test_guid_unlocks_via_graph_subscribedskus_fixture():
    """End-to-end: a Graph subscribedSkus value with the GUID survives parsing."""
    caps, guid = _entra_capability()
    values = [
        {
            "skuId": "sku-guid-test",
            "skuPartNumber": "CUSTOM_SKU_XYZ",
            "capabilityStatus": "Enabled",
            "consumedUnits": 5,
            "prepaidUnits": {"enabled": 10},
            "servicePlans": [
                {
                    "servicePlanId": guid,
                    "servicePlanName": "COMPLETELY_RENAMED_PLAN",
                    "provisioningStatus": "Success",
                },
            ],
        }
    ]
    skus = skus_from_graph_values(values)
    owned = resolve_owned_capabilities(caps, skus)
    assert "entra_id_p2" in owned


def test_name_fallback_still_unlocks_without_guid():
    """Backwards compatibility: a matching name with no GUID still unlocks."""
    caps, _ = _entra_capability()
    skus = [_sku_with_plan("SPE_E5", "AAD_PREMIUM_P2", plan_id=None)]
    owned = resolve_owned_capabilities(caps, skus)
    assert "entra_id_p2" in owned


def test_known_name_with_unknown_guid_still_unlocks_via_fallback():
    """A plan whose name matches but GUID is unknown must not lose its unlock."""
    caps, _ = _entra_capability()
    skus = [
        _sku_with_plan(
            "SPE_E5",
            "AAD_PREMIUM_P2",
            plan_id="00000000-0000-0000-0000-000000000000",
        )
    ]
    owned = resolve_owned_capabilities(caps, skus)
    assert "entra_id_p2" in owned


def test_guid_with_unknown_name_does_not_unlock_unrelated_capabilities():
    """A GUID unlocks exactly the capabilities that name it, nothing else."""
    caps, guid = _entra_capability()
    skus = [_sku_with_plan("CUSTOM_SKU_XYZ", "SOMETHING_ELSE_ENTIRELY", plan_id=guid)]
    owned = resolve_owned_capabilities(caps, skus)
    assert set(owned) == {"entra_id_p2", "conditional_access", "identity_protection"}


def test_disabled_plan_guid_never_unlocks():
    """GUID matching still respects provisioning status."""
    caps, guid = _entra_capability()
    skus = [
        _sku_with_plan(
            "CUSTOM_SKU_XYZ",
            "AAD_PREMIUM_P2_RENAMED",
            plan_id=guid,
            plan_status="Disabled",
        )
    ]
    owned = resolve_owned_capabilities(caps, skus)
    assert owned == []


def test_disabled_sku_guid_never_unlocks():
    caps, guid = _entra_capability()
    skus = [
        _sku_with_plan(
            "CUSTOM_SKU_XYZ",
            "AAD_PREMIUM_P2_RENAMED",
            plan_id=guid,
            sku_status="Disabled",
        )
    ]
    owned = resolve_owned_capabilities(caps, skus)
    assert owned == []


def test_guid_case_variation_still_matches():
    """GUIDs are normalized: uppercase Graph GUIDs still intersect."""
    caps, guid = _entra_capability()
    skus = [_sku_with_plan("CUSTOM_SKU_XYZ", "RENAMED_AGAIN", plan_id=guid.upper())]
    owned = resolve_owned_capabilities(caps, skus)
    assert set(owned) == {"entra_id_p2", "conditional_access", "identity_protection"}


def test_guid_matched_summary_keeps_provenance():
    """A GUID-only match must not render an empty 'not reported' provenance."""
    caps, guid = _entra_capability()
    skus = [_sku_with_plan("CUSTOM_SKU_XYZ", "AAD_PREMIUM_P2_RENAMED", plan_id=guid)]
    owned = resolve_owned_capabilities(caps, skus)
    summaries = capability_summaries_for(caps, owned, skus)
    assert {summary.id for summary in summaries} == {
        "entra_id_p2",
        "conditional_access",
        "identity_protection",
    }
    for summary in summaries:
        assert summary.matched_service_plans == ["AAD_PREMIUM_P2_RENAMED"]
        assert summary.matched_skus == ["CUSTOM_SKU_XYZ"]


def test_catalog_self_consistency_no_guid_maps_to_two_capabilities():
    """Every GUID in the catalog maps to exactly one capability (offline check)."""
    violations = validate_sku_catalog.validate_sku_catalog()
    assert violations == [], f"catalog GUID violations: {violations}"


def test_load_capabilities_is_fail_closed_on_guid_problems(tmp_path: Path):
    """The loader itself rejects blank/malformed GUIDs, naming the capability."""
    source = Path("catalog/capabilities.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(source)
    data["capabilities"][0]["service_plan_ids"] = [""]
    path = tmp_path / "capabilities.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(CatalogLoadError) as exc_info:
        load_capabilities(path)
    assert any(
        diagnostic.startswith("invalid_service_plan_id:entra_id_p2:")
        for diagnostic in exc_info.value.diagnostics
    )


def test_duplicate_guid_within_capability_is_collision(tmp_path: Path):
    """The same GUID twice on one capability is a load-time catalog error."""
    source = Path("catalog/capabilities.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(source)
    guid = data["capabilities"][0]["service_plan_ids"][0]
    data["capabilities"][0]["service_plan_ids"].append(guid)
    path = tmp_path / "capabilities.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(CatalogLoadError) as exc_info:
        load_capabilities(path)
    diagnostics = exc_info.value.diagnostics
    assert any(d.startswith("duplicate_service_plan_id:entra_id_p2:") for d in diagnostics)


def test_shared_guid_across_capabilities_is_allowed():
    """A service plan GUID may legitimately unlock several capabilities."""
    caps = load_capabilities()
    guid_to_caps: dict[str, list[str]] = {}
    for cap in caps:
        for guid in cap.service_plan_ids:
            guid_to_caps.setdefault(guid.lower(), []).append(cap.id)
    shared = [guid for guid, owners in guid_to_caps.items() if len(owners) > 1]
    assert shared, "expected at least one shared service plan GUID (e.g. AAD_PREMIUM_P2)"


def test_validator_script_accepts_repo_catalog():
    """The offline validator exits clean against the shipped catalog."""
    import subprocess

    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "validate_sku_catalog.py")],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"validator failed:\n{result.stdout}\n{result.stderr}"
