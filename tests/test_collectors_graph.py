"""Collector tests using FakeGraphClient — no network calls."""

from tests.fake_clients import FakeGraphClient, error, ok, paginated


# ---------------------------------------------------------------------------
# SKUs
# ---------------------------------------------------------------------------

def test_collect_skus_live_empty():
    from licenselens.collectors.skus import collect_subscribed_skus_live

    fake = FakeGraphClient()
    fake.register_list("/subscribedSkus", ok({"value": []}))
    result = collect_subscribed_skus_live(fake)
    assert isinstance(result, list)
    assert len(result) == 0


def test_collect_skus_live_single():
    from licenselens.collectors.skus import collect_subscribed_skus_live

    fake = FakeGraphClient()
    fake.register_list(
        "/subscribedSkus",
        ok(
            {
                "value": [
                    {
                        "skuId": "sku-a",
                        "skuPartNumber": "SPE_E5",
                        "capabilityStatus": "Enabled",
                        "consumedUnits": 87,
                        "prepaidUnits": {"enabled": 100},
                        "servicePlans": [
                            {
                                "servicePlanName": "AAD_PREMIUM_P2",
                                "provisioningStatus": "Success",
                            }
                        ],
                    }
                ]
            }
        ),
    )
    result = collect_subscribed_skus_live(fake)
    assert len(result) == 1
    sku = result[0]
    assert sku.sku_part_number == "SPE_E5"
    assert sku.prepaid_units == 100
    assert sku.consumed_units == 87
    assert len(sku.service_plans) == 1
    assert sku.service_plans[0].service_plan_name == "AAD_PREMIUM_P2"


def test_collect_skus_graph_error():
    from licenselens.collectors.skus import collect_subscribed_skus_live
    from licenselens.errors import GraphError

    fake = FakeGraphClient()
    fake.register_list("/subscribedSkus", error(403, "Forbidden"))
    try:
        collect_subscribed_skus_live(fake)
    except GraphError as exc:
        assert exc.status_code == 403


# ---------------------------------------------------------------------------
# Conditional Access
# ---------------------------------------------------------------------------

def test_collect_ca_policies_empty():
    from licenselens.collectors.conditional_access import collect_ca_policies

    fake = FakeGraphClient()
    fake.register_list("/identity/conditionalAccess/policies", ok({"value": []}))
    result = collect_ca_policies(fake)
    assert result == []


def test_collect_ca_policies_paginated():
    from licenselens.collectors.conditional_access import collect_ca_policies

    page1 = [
        {
            "id": "p1",
            "displayName": "Policy One",
            "state": "enabled",
            "grantControls": {"builtInControls": ["mfa"]},
        }
    ]
    page2 = [
        {
            "id": "p2",
            "displayName": "Policy Two",
            "state": "disabled",
            "grantControls": {},
        }
    ]
    fake = FakeGraphClient()
    fake.register_list(
        "/identity/conditionalAccess/policies", paginated(page1, page2)
    )
    result = collect_ca_policies(fake)
    assert len(result) == 2
    assert result[0]["id"] == "p1"
    assert result[1]["id"] == "p2"


# ---------------------------------------------------------------------------
# Privileged roles
# ---------------------------------------------------------------------------

def test_collect_role_assignments():
    from licenselens.collectors.privileged_roles import collect_role_assignments

    fake = FakeGraphClient()
    fake.register_list(
        "/roleManagement/directory/roleAssignments",
        ok(
            {
                "value": [
                    {
                        "id": "ra-1",
                        "principalId": "u1",
                        "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
                        "directoryScopeId": "/",
                    }
                ]
            }
        ),
    )
    result = collect_role_assignments(fake)
    assert len(result) == 1
    assert result[0]["id"] == "ra-1"


def test_collect_role_eligibility_empty():
    from licenselens.collectors.privileged_roles import (
        collect_role_eligibility_schedules,
    )

    fake = FakeGraphClient()
    fake.register_list(
        "/roleManagement/directory/roleEligibilitySchedules",
        ok({"value": []}),
    )
    result = collect_role_eligibility_schedules(fake)
    assert result == []


# ---------------------------------------------------------------------------
# Secure Score
# ---------------------------------------------------------------------------

def test_collect_latest_secure_score():
    from licenselens.collectors.secure_score import collect_latest_secure_score

    fake = FakeGraphClient()
    fake.register_get(
        "/security/secureScores",
        ok(
            {
                "value": [
                    {
                        "id": "ss-1",
                        "currentScore": 75.0,
                        "maxScore": 100.0,
                        "controlScores": [],
                    }
                ]
            }
        ),
    )
    result = collect_latest_secure_score(fake)
    assert result is not None
    assert result["currentScore"] == 75.0


def test_collect_latest_secure_score_empty():
    from licenselens.collectors.secure_score import collect_latest_secure_score

    fake = FakeGraphClient()
    fake.register_get("/security/secureScores", ok({"value": []}))
    result = collect_latest_secure_score(fake)
    assert result is None


def test_collect_secure_score_control_profiles():
    from licenselens.collectors.secure_score import (
        collect_secure_score_control_profiles,
    )

    fake = FakeGraphClient()
    fake.register_list(
        "/security/secureScoreControlProfiles",
        ok(
            {
                "value": [
                    {
                        "controlName": "SafeLinks_Enabled",
                        "title": "Safe Links",
                    },
                    {
                        "controlName": "MDE_Onboard",
                        "title": "Defender for Endpoint",
                    },
                ]
            }
        ),
    )
    result = collect_secure_score_control_profiles(fake)
    assert len(result) == 2
    assert result[0]["controlName"] == "SafeLinks_Enabled"


def test_extract_control_scores_none():
    from licenselens.collectors.secure_score import extract_control_scores

    assert extract_control_scores(None) == []


def test_control_matches_mdo_hints():
    from licenselens.collectors.secure_score import (
        MDO_CONTROL_HINTS,
        control_matches,
    )

    assert control_matches(
        {"controlName": "SafeLinks_Enabled", "title": "Safe Links"}, MDO_CONTROL_HINTS
    )
    assert not control_matches(
        {"controlName": "SomeOther_Thing", "title": "Not MDO"}, MDO_CONTROL_HINTS
    )
    assert control_matches(
        {"controlName": "AntiPhish_Policy", "description": "anti-phishing"},
        MDO_CONTROL_HINTS,
    )


def test_summarize_controls_zero():
    from licenselens.collectors.secure_score import summarize_controls

    result = summarize_controls([], ("nonexistent_hint",))
    assert result["matched_count"] == 0
    assert result["ratio"] is None


def test_secure_score_403_is_handled():
    from licenselens.collectors.secure_score import collect_latest_secure_score
    from licenselens.errors import GraphError

    fake = FakeGraphClient()
    fake.register_get("/security/secureScores", error(403, "Forbidden"))
    try:
        collect_latest_secure_score(fake)
    except GraphError as exc:
        assert exc.status_code == 403


# ---------------------------------------------------------------------------
# Sign-ins
# ---------------------------------------------------------------------------

def test_collect_recent_signins_empty():
    from licenselens.collectors.signins import (
        collect_recent_success_signin_user_ids,
    )

    fake = FakeGraphClient()
    fake.register_list("/auditLogs/signIns", ok({"value": []}))
    result = collect_recent_success_signin_user_ids(fake, lookback_days=90)
    assert isinstance(result, set)
    assert len(result) == 0


def test_collect_recent_signins_extracts_user_ids():
    from licenselens.collectors.signins import (
        collect_recent_success_signin_user_ids,
    )

    fake = FakeGraphClient()
    fake.register_list(
        "/auditLogs/signIns",
        ok(
            {
                "value": [
                    {"userId": "user-a", "status": {"errorCode": 0}},
                    {"userId": "user-b", "status": {"errorCode": 0}},
                    {},  # no userId — skipped
                    {"userId": "user-a"},  # duplicate
                ]
            }
        ),
    )
    result = collect_recent_success_signin_user_ids(fake, lookback_days=90)
    assert result == {"user-a", "user-b"}


def test_collect_directory_objects_by_ids():
    from licenselens.collectors.signins import collect_directory_objects_by_ids

    fake = FakeGraphClient()
    fake.register_post(
        "/directoryObjects/getByIds",
        ok(
            {
                "value": [
                    {
                        "id": "user-a",
                        "userPrincipalName": "a@example.com",
                        "@odata.type": "#microsoft.graph.user",
                    }
                ]
            }
        ),
    )
    result = collect_directory_objects_by_ids(fake, ["user-a"])
    assert "user-a" in result
    assert result["user-a"]["userPrincipalName"] == "a@example.com"


def test_collect_directory_objects_chunks():
    from licenselens.collectors.signins import collect_directory_objects_by_ids

    fake = FakeGraphClient()
    ids_called: list[list[str]] = []

    def handler(_path: str, body: dict[str, Any] | None) -> dict[str, Any]:
        chunk = (body or {}).get("ids", [])
        ids_called.append(chunk)
        return {"value": [{"id": i} for i in chunk]}

    fake.register_post("/directoryObjects/getByIds", handler)
    ids = [f"u-{i:03d}" for i in range(45)]
    result = collect_directory_objects_by_ids(fake, ids)
    assert len(result) == 45
    assert len(ids_called) == 3  # chunk_size=20
    assert ids_called[0] == ids[0:20]
    assert ids_called[-1] == ids[40:]


# ---------------------------------------------------------------------------
# Organization context
# ---------------------------------------------------------------------------

def test_fetch_organization_context():
    from licenselens.graph import fetch_organization_context

    fake = FakeGraphClient()
    fake.register_list(
        "/organization",
        ok(
            {
                "value": [
                    {
                        "id": "tenant-guid",
                        "displayName": "Contoso",
                    }
                ]
            }
        ),
    )
    tid, name = fetch_organization_context(fake)
    assert tid == "tenant-guid"
    assert name == "Contoso"


def test_fetch_organization_context_empty():
    from licenselens.graph import fetch_organization_context

    fake = FakeGraphClient()
    fake.register_list("/organization", ok({"value": []}))
    tid, name = fetch_organization_context(fake)
    assert tid is None
    assert name is None


def test_fetch_organization_context_error():
    from licenselens.graph import fetch_organization_context

    fake = FakeGraphClient()
    fake.register_list("/organization", error(403, "Forbidden"))
    tid, name = fetch_organization_context(fake)
    assert tid is None
    assert name is None
