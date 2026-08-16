"""Direct-evidence conversion tests for the four proxy/manual→direct checks."""

from __future__ import annotations

import pytest

from licenselens.collectors.pbi_admin import (
    DEMO_PBI_CAPACITY_BUNDLE,
    PowerBiAdminError,
    collect_pbi_capacity_bundle,
)
from licenselens.collectors.purview import (
    DEMO_DLP_GRAPH_BUNDLE,
    DEMO_EDISCOVERY_BUNDLE,
    DEMO_INSIDER_RISK_BUNDLE,
    collect_purview_dlp_bundle,
    collect_purview_ediscovery_bundle,
    collect_purview_insider_risk_bundle,
)
from licenselens.evaluators.power_bi import evaluate_pbi_premium_capacity_governance
from licenselens.evaluators.purview import (
    evaluate_pur_ediscovery_readiness,
    evaluate_pur_insider_risk_readiness,
    evaluate_purview_dlp,
)
from licenselens.models import CheckDefinition, FindingStatus, Workload
from tests.fake_clients import FakeGraphClient, error, ok


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=Workload.PURVIEW)


# --- pur-dlp-not-enforced (direct Graph + proxy fallback) ---------------------


def test_purview_dlp_direct_enforced_ok():
    result = evaluate_purview_dlp(
        _check("pur-dlp-not-enforced"),
        {"purview_dlp": DEMO_DLP_GRAPH_BUNDLE},
    )
    assert result.status is FindingStatus.OK
    assert result.evidence["proxy"] is False
    assert result.evidence["direct"] is True


def test_purview_dlp_direct_all_test_mode_gap():
    bundle = {
        "dlp_graph": {
            "policy_count": 2,
            "enforced_count": 0,
            "test_or_other_count": 2,
            "policy_names": ["policy-a", "policy-b"],
            "apps": {"count": 3, "states": ["enabled"]},
            "source": "graph.security.dataLossPrevention",
            "direct": True,
        },
        "dlp_secure_score": None,
        "proxy": False,
    }
    result = evaluate_purview_dlp(_check("pur-dlp-not-enforced"), {"purview_dlp": bundle})
    assert result.status is FindingStatus.GAP


def test_purview_dlp_direct_no_policies_gap():
    bundle = {
        "dlp_graph": {
            "policy_count": 0,
            "enforced_count": 0,
            "test_or_other_count": 0,
            "policy_names": [],
            "apps": {"count": 0, "states": []},
            "source": "graph.security.dataLossPrevention",
            "direct": True,
        },
        "dlp_secure_score": None,
        "proxy": False,
    }
    result = evaluate_purview_dlp(_check("pur-dlp-not-enforced"), {"purview_dlp": bundle})
    assert result.status is FindingStatus.GAP


# --- pur-ediscovery-readiness (direct Graph v1.0) -----------------------------


def test_purview_ediscovery_cases_ok():
    result = evaluate_pur_ediscovery_readiness(
        _check("pur-ediscovery-readiness"),
        {"purview_ediscovery": DEMO_EDISCOVERY_BUNDLE},
    )
    assert result.status is FindingStatus.OK
    assert result.evidence["case_count"] == 1


def test_purview_ediscovery_empty_partial():
    result = evaluate_pur_ediscovery_readiness(
        _check("pur-ediscovery-readiness"),
        {"purview_ediscovery": {"case_count": 0, "case_names": []}},
    )
    assert result.status is FindingStatus.PARTIAL


# --- pur-insider-risk-readiness (direct Graph beta) ---------------------------


def test_purview_insider_risk_policy_ok():
    result = evaluate_pur_insider_risk_readiness(
        _check("pur-insider-risk-readiness"),
        {"purview_insider_risk": DEMO_INSIDER_RISK_BUNDLE},
    )
    assert result.status is FindingStatus.OK
    assert result.evidence["policy_count"] == 1


def test_purview_insider_risk_none_gap():
    result = evaluate_pur_insider_risk_readiness(
        _check("pur-insider-risk-readiness"),
        {"purview_insider_risk": {"policy_count": 0, "policy_names": []}},
    )
    assert result.status is FindingStatus.GAP


# --- pbi-premium-capacity-governance (Power BI admin REST) --------------------


def test_pbi_premium_capacity_governance_ok():
    result = evaluate_pbi_premium_capacity_governance(
        _check("pbi-premium-capacity-governance"),
        {"pbi_capacity_bundle": DEMO_PBI_CAPACITY_BUNDLE},
    )
    assert result.status is FindingStatus.OK
    assert result.evidence["capacity_count"] == 1


def test_pbi_premium_capacity_governance_none_partial():
    result = evaluate_pbi_premium_capacity_governance(
        _check("pbi-premium-capacity-governance"),
        {
            "pbi_capacity_bundle": {
                "capacity_count": 0,
                "capacities": [],
                "tenant_setting_count": 40,
                "total_admin_count": 0,
                "source": "powerbi.admin.rest",
                "direct": True,
                "proxy": False,
            }
        },
    )
    assert result.status is FindingStatus.PARTIAL


# --- collector-level direct reads (Graph-shaped fixtures) ---------------------


def test_dlp_collector_prefers_direct_graph_over_proxy():
    fake = FakeGraphClient()
    fake.register_list(
        "/security/dataLossPreventionPolicies",
        ok({"value": [{"id": "1", "name": "p", "mode": "production"}]}),
    )
    fake.register_list(
        "/security/dataLossPreventionApps",
        ok({"value": [{"id": "a1", "state": "enabled"}]}),
    )
    bundle = collect_purview_dlp_bundle(fake, [])
    assert bundle["proxy"] is False
    assert bundle["dlp_graph"]["enforced_count"] == 1


def test_dlp_collector_falls_back_to_proxy_when_graph_fails():
    fake = FakeGraphClient()
    fake.register_list("/security/dataLossPreventionPolicies", error(403, "denied"))
    bundle = collect_purview_dlp_bundle(
        fake,
        [
            {
                "controlName": "DLP_Policies_Enabled",
                "description": "DLP",
                "score": 0.1,
                "maxScore": 1.0,
            }
        ],
    )
    assert bundle["proxy"] is True
    assert bundle["dlp_graph"] is None
    assert bundle["dlp_secure_score"]["matched_count"] == 1


def test_ediscovery_collector_reads_cases():
    fake = FakeGraphClient()
    fake.register_list(
        "/security/cases/ediscoveryCases",
        ok({"value": [{"id": "c1", "displayName": "Case A"}]}),
    )
    bundle = collect_purview_ediscovery_bundle(fake)
    assert bundle["case_count"] == 1
    assert bundle["case_names"] == ["Case A"]


def test_insider_risk_collector_reads_policies():
    fake = FakeGraphClient(allow_preview=True)
    fake.register_list(
        "/security/insiderRiskManagement/policies",
        ok({"value": [{"id": "p1", "name": "departing users"}]}),
    )
    bundle = collect_purview_insider_risk_bundle(fake)
    assert bundle["policy_count"] == 1


def test_pbi_admin_rest_403_raises_actionable_error(monkeypatch: pytest.MonkeyPatch):

    from licenselens import collectors

    class _FakeCredential:
        def get_token(self, _scope: str):
            return type("Token", (), {"token": "fake"})()

    from licenselens.auth import AuthContext, AuthMode

    auth = AuthContext(mode=AuthMode.CLIENT_SECRET, credential=_FakeCredential())

    class _Response:
        status_code = 403

        def json(self):
            return {}

    class _Client:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def get(self, _url, *, headers=None):
            return _Response()

    monkeypatch.setattr(collectors.pbi_admin.httpx, "Client", _Client)
    with pytest.raises(PowerBiAdminError, match="Tenant.Read.All"):
        collect_pbi_capacity_bundle(auth)
