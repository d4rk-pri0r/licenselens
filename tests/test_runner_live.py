"""Runner live-path integration test using FakeGraphClient — no network."""

from licenselens.auth import AuthContext, AuthMode


def _auth() -> AuthContext:
    return AuthContext(mode=AuthMode.CLIENT_SECRET, tenant_id="live-tenant")


def _live_results(monkeypatch, fake, workspace_resource_id=None):
    """Invoke run_scan in live mode with a mocked GraphClient."""
    monkeypatch.setattr(
        "licenselens.engine.runner.GraphClient",
        lambda _auth, **_kw: fake,
    )
    monkeypatch.setattr(
        "licenselens.engine.runner.collect_mde_machine_summary",
        lambda _auth: {
            "onboarded_machines": 50,
            "sample_size": 50,
            "count_method": "test",
            "truncated": False,
        },
    )
    monkeypatch.setattr(
        "licenselens.engine.runner.collect_sentinel_bundle",
        lambda _auth, _wid: {
            "sentinel_rules": {"total_rules": 0},
            "sentinel_ueba": {},
            "workspace_resource_id": _wid,
        },
    )
    monkeypatch.setattr(
        "licenselens.collectors.workspace_discover.discover_sentinel_workspaces",
        lambda _auth: [],
    )
    from licenselens.engine.runner import run_scan

    return run_scan(
        _auth(),
        dry_run=False,
        workspace_resource_id=workspace_resource_id,
        allow_email_proxy=True,
    )


# ---------------------------------------------------------------------------
# Happy path: every collector returns valid data
# ---------------------------------------------------------------------------


def test_live_scan_all_collectors_respond(monkeypatch):
    from tests.fake_clients import FakeGraphClient, ok

    fake = FakeGraphClient()

    # Organization
    fake.register_list(
        "/organization",
        ok({"value": [{"id": "t-1", "displayName": "LiveCo"}]}),
    )
    # SKUs
    fake.register_list(
        "/subscribedSkus",
        ok(
            {
                "value": [
                    {
                        "skuId": "e5",
                        "skuPartNumber": "SPE_E5",
                        "capabilityStatus": "Enabled",
                        "consumedUnits": 50,
                        "prepaidUnits": {"enabled": 100},
                        "servicePlans": [
                            {
                                "servicePlanName": "AAD_PREMIUM_P2",
                                "provisioningStatus": "Success",
                            },
                            {
                                "servicePlanName": "DEFENDER_ENDPOINT_P2",
                                "provisioningStatus": "Success",
                            },
                            {
                                "servicePlanName": "ADALLOM_S_O365",
                                "provisioningStatus": "Success",
                            },
                            {
                                "servicePlanName": "MIP_S_CLP2",
                                "provisioningStatus": "Success",
                            },
                            {
                                "servicePlanName": "THREAT_INTELLIGENCE",
                                "provisioningStatus": "Success",
                            },
                        ],
                    },
                ]
            }
        ),
    )
    # CA policies
    fake.register_list(
        "/identity/conditionalAccess/policies",
        ok({"value": []}),
    )
    # Role assignments
    fake.register_list(
        "/roleManagement/directory/roleAssignments",
        ok({"value": []}),
    )
    # Role eligibility schedules
    fake.register_list(
        "/roleManagement/directory/roleEligibilitySchedules",
        ok({"value": []}),
    )
    # Sign-ins (empty = no active users = everyone looks dormant)
    fake.register_list("/auditLogs/signIns", ok({"value": []}))
    # Secure Score
    fake.register_get(
        "/security/secureScores",
        ok(
            {
                "value": [
                    {
                        "id": "ss-1",
                        "currentScore": 50.0,
                        "maxScore": 100.0,
                        "controlScores": [],
                    }
                ]
            }
        ),
    )
    # Security defaults & access reviews
    fake.register_get(
        "/policies/identitySecurityDefaultsEnforcementPolicy",
        ok({"id": "sd-1", "isEnabled": True}),
    )
    fake.register_list(
        "/identityGovernance/accessReviews/definitions",
        ok({"value": []}),
    )

    result = _live_results(monkeypatch, fake)
    assert result.scan_mode == "live"
    assert result.tenant_display_name == "LiveCo"
    assert len(result.findings) >= 8
    assert result.has_actionable_gaps


# ---------------------------------------------------------------------------
# Some collectors fail → partial card still produced
# ---------------------------------------------------------------------------


def test_live_scan_partial_collector_failures(monkeypatch):
    from tests.fake_clients import FakeGraphClient, error, ok

    fake = FakeGraphClient()

    fake.register_list(
        "/organization",
        ok({"value": [{"id": "t-2", "displayName": "PartialCo"}]}),
    )
    fake.register_list(
        "/subscribedSkus",
        ok(
            {
                "value": [
                    {
                        "skuId": "e5",
                        "skuPartNumber": "SPE_E5",
                        "capabilityStatus": "Enabled",
                        "consumedUnits": 50,
                        "prepaidUnits": {"enabled": 100},
                        "servicePlans": [
                            {
                                "servicePlanName": "AAD_PREMIUM_P2",
                                "provisioningStatus": "Success",
                            },
                        ],
                    },
                ]
            }
        ),
    )
    # CA fails
    fake.register_list(
        "/identity/conditionalAccess/policies", error(403)
    )
    # Roles OK
    fake.register_list(
        "/roleManagement/directory/roleAssignments",
        ok({"value": []}),
    )
    fake.register_list(
        "/roleManagement/directory/roleEligibilitySchedules",
        ok({"value": []}),
    )
    fake.register_list("/auditLogs/signIns", ok({"value": []}))
    fake.register_get(
        "/security/secureScores",
        ok(
            {
                "value": [
                    {"id": "ss-1", "currentScore": 50.0, "maxScore": 100.0, "controlScores": []}
                ]
            }
        ),
    )

    result = _live_results(monkeypatch, fake)
    assert result.scan_mode == "live"
    assert any("Conditional Access" in w or "403" in w for w in result.warnings)
    # Still got some findings
    assert len(result.findings) >= 1
    assert sum(1 for f in result.findings if f.status.value == "error") >= 1


# ---------------------------------------------------------------------------
# empty SKUs → limited findings
# ---------------------------------------------------------------------------


def test_live_scan_empty_skus_minimal_findings(monkeypatch):
    from tests.fake_clients import FakeGraphClient, ok

    fake = FakeGraphClient()

    fake.register_list(
        "/organization",
        ok({"value": [{"id": "t-3", "displayName": "EmptySkuCo"}]}),
    )
    fake.register_list("/subscribedSkus", ok({"value": []}))
    fake.register_list("/identity/conditionalAccess/policies", ok({"value": []}))
    fake.register_list("/roleManagement/directory/roleAssignments", ok({"value": []}))
    fake.register_list(
        "/roleManagement/directory/roleEligibilitySchedules", ok({"value": []})
    )
    fake.register_list("/auditLogs/signIns", ok({"value": []}))
    fake.register_get(
        "/security/secureScores",
        ok(
            {
                "value": [
                    {"id": "ss-1", "currentScore": 0.0, "maxScore": 100.0, "controlScores": []}
                ]
            }
        ),
    )

    result = _live_results(monkeypatch, fake)
    assert result.scan_mode == "live"
    assert result.capability_rollup.you_own == 0
    # All findings should be not_licensed
    for f in result.findings:
        assert f.status.value == "not_licensed", f"{f.check_id}: {f.status}"
