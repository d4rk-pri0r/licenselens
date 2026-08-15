"""Wave 2 todo 16 — expanded Graph/REST collectors + permission/cloud matrix."""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from licenselens.auth import REQUIRED_GRAPH_APP_PERMISSIONS, AuthContext, AuthMode
from licenselens.cloud_endpoints import endpoints_for, graph_base_url
from licenselens.collectors.applications import (
    collect_applications_bundle,
    collect_applications_evidence,
)
from licenselens.collectors.arm_selective import (
    SELECTIVE_ARM_OPERATIONS,
    collect_selective_arm_evidence,
)
from licenselens.collectors.auth_methods import (
    collect_auth_methods_bundle,
    collect_auth_methods_evidence,
)
from licenselens.collectors.contracts import CloudEnvironment, EvidenceHealth
from licenselens.collectors.graph_collect import collect_graph_operation
from licenselens.collectors.guests import collect_guests_bundle, collect_guests_evidence
from licenselens.collectors.intune import collect_intune_bundle, collect_intune_evidence
from licenselens.collectors.mde_health import (
    collect_mde_health_evidence,
    collect_mde_health_summary,
)
from licenselens.collectors.named_locations import (
    collect_named_locations,
    collect_named_locations_evidence,
)
from licenselens.collectors.pim_policies import (
    collect_pim_policies_bundle,
    collect_pim_policies_evidence,
)
from licenselens.collectors.security_alerts import (
    collect_security_alerts_bundle,
    collect_security_alerts_evidence,
)
from licenselens.errors import AuthError, GraphError
from licenselens.graph import GraphClient
from licenselens.graph_ops import (
    ApiFamily,
    WritePermissionError,
    all_application_permissions,
    get_operation,
    iter_operations,
)
from tests.fake_clients import FakeArmClient, FakeGraphClient, FakeMdeClient, error, ok, paginated


class _FakeToken:
    token = "test-token"


def _auth() -> AuthContext:
    cred = MagicMock()
    cred.get_token.return_value = _FakeToken()
    return AuthContext(mode=AuthMode.CLIENT_SECRET, tenant_id="t1", credential=cred)


def _seed_happy_graph(fake: FakeGraphClient) -> None:
    fake.register_get(
        "/policies/authenticationMethodsPolicy",
        ok({"id": "authenticationMethodsPolicy", "policyMigrationState": "preMigration"}),
    )
    fake.register_list(
        "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations",
        ok({"value": [{"id": "sms", "state": "enabled"}]}),
    )
    fake.register_list(
        "/policies/authenticationStrengthPolicies",
        ok({"value": [{"id": "s1", "displayName": "MFA"}]}),
    )
    fake.register_list(
        "/identity/conditionalAccess/namedLocations",
        ok({"value": [{"id": "nl1", "displayName": "HQ"}]}),
    )
    fake.register_list(
        "/policies/roleManagementPolicies",
        ok({"value": [{"id": "p1", "scopeType": "DirectoryRole"}]}),
    )
    fake.register_list(
        "/policies/roleManagementPolicyAssignments",
        ok({"value": [{"id": "a1", "policyId": "p1"}]}),
    )
    fake.register_list(
        "/applications",
        ok({"value": [{"id": "app1", "displayName": "App"}]}),
    )
    fake.register_list(
        "/servicePrincipals",
        ok({"value": [{"id": "sp1", "displayName": "SP"}]}),
    )
    fake.register_list(
        "/oauth2PermissionGrants",
        ok({"value": [{"id": "g1", "scope": "User.Read"}]}),
    )
    fake.register_get(
        "/policies/crossTenantAccessPolicy",
        ok({"displayName": "CrossTenantAccessPolicy"}),
    )
    fake.register_get(
        "/policies/crossTenantAccessPolicy/default",
        ok({"inboundTrust": {}}),
    )
    fake.register_list(
        "/policies/crossTenantAccessPolicy/partners",
        ok({"value": []}),
    )
    fake.register_list(
        "/users",
        ok({"value": [{"id": "guest1", "userType": "Guest"}]}),
    )
    fake.register_list(
        "/deviceManagement/deviceCompliancePolicies",
        ok({"value": [{"id": "c1"}]}),
    )
    fake.register_list(
        "/deviceManagement/deviceConfigurations",
        ok({"value": [{"id": "cfg1"}]}),
    )
    fake.register_list(
        "/deviceManagement/configurationPolicies",
        ok({"value": [{"id": "ep1", "name": "Antivirus"}]}),
    )
    fake.register_list(
        "/deviceManagement/managedDevices",
        ok({"value": [{"id": "d1", "complianceState": "compliant"}]}),
    )
    fake.register_list(
        "/security/incidents",
        ok({"value": [{"id": "i1", "status": "active"}]}),
    )
    fake.register_list(
        "/security/alerts_v2",
        ok({"value": [{"id": "al1", "severity": "medium"}]}),
    )


def test_cloud_endpoints_sovereign_roots() -> None:
    public = endpoints_for(CloudEnvironment.PUBLIC)
    gov = endpoints_for(CloudEnvironment.US_GOV)
    china = endpoints_for(CloudEnvironment.CHINA)

    assert public.graph_resource == "https://graph.microsoft.com"
    assert gov.graph_resource == "https://graph.microsoft.us"
    assert china.graph_resource == "https://microsoftgraph.chinacloudapi.cn"
    assert gov.arm_resource == "https://management.usgovcloudapi.net"
    assert china.mde_supported is False
    assert graph_base_url(CloudEnvironment.US_GOV).endswith("/v1.0")


def test_operation_matrix_read_only_and_no_beta_without_preview() -> None:
    ops = iter_operations()
    assert len(ops) >= 20
    for op in ops:
        for perm in (*op.application_permissions, *op.delegated_permissions):
            lowered = perm.lower()
            assert "readwrite" not in lowered
            assert not lowered.endswith(".write")
        if op.api_version == "beta":
            assert op.preview is True
        if op.preview:
            assert op.api_version == "beta"


def test_write_permission_rejected_at_construction() -> None:
    from licenselens.graph_ops import GraphOperation

    with pytest.raises(WritePermissionError):
        GraphOperation(
            operation_id="bad",
            family=ApiFamily.GRAPH,
            path="/foo",
            evidence_key="graph.bad",
            application_permissions=("Policy.ReadWrite.All",),
            delegated_permissions=(),
        )


def test_required_permissions_cover_graph_application_matrix() -> None:
    matrix = set(all_application_permissions(family=ApiFamily.GRAPH))
    required = set(REQUIRED_GRAPH_APP_PERMISSIONS)
    # plus Directory.Read.All may substitute some grants — required must include matrix.
    missing = matrix - required
    # Directory.Read.All is an alternate for some ops; still require explicit least-priv names
    assert not missing, f"docs/auth missing permissions: {sorted(missing)}"


def test_happy_path_collectors_and_evidence_envelopes() -> None:
    fake = FakeGraphClient()
    _seed_happy_graph(fake)

    auth_bundle = collect_auth_methods_bundle(fake)
    assert auth_bundle["policy"]["id"] == "authenticationMethodsPolicy"
    assert len(auth_bundle["strengths"]) == 1

    assert collect_named_locations(fake)[0]["id"] == "nl1"
    pim = collect_pim_policies_bundle(fake)
    assert pim["policies"][0]["id"] == "p1"
    apps = collect_applications_bundle(fake)
    assert apps["applications"][0]["id"] == "app1"
    guests = collect_guests_bundle(fake)
    assert guests["guests"][0]["userType"] == "Guest"
    intune = collect_intune_bundle(fake)
    assert intune["configuration_policies"][0]["id"] == "ep1"
    sec = collect_security_alerts_bundle(fake)
    assert sec["capability_operating"] is True

    envelopes = {
        **collect_auth_methods_evidence(fake),
        "named": collect_named_locations_evidence(fake),
        **collect_pim_policies_evidence(fake),
        **collect_applications_evidence(fake),
        **collect_guests_evidence(fake),
        **collect_intune_evidence(fake),
        **collect_security_alerts_evidence(fake),
    }
    assert all(env.health is EvidenceHealth.OK for env in envelopes.values())


def test_endpoint_permission_matrix_keys() -> None:
    expected = {
        "auth_methods_policy",
        "auth_strength_policies",
        "ca_named_locations",
        "pim_role_management_policies",
        "applications",
        "service_principals",
        "oauth2_permission_grants",
        "cross_tenant_access_default",
        "guest_users",
        "intune_compliance_policies",
        "intune_configuration_policies",
        "security_incidents",
        "security_alerts_v2",
        "mde_machine_health",
        "arm_defender_for_cloud_pricings",
    }
    present = {op.operation_id for op in iter_operations()}
    assert expected <= present
    ca = get_operation("ca_named_locations")
    assert ca.application_permissions == ("Policy.Read.All",)
    assert ca.path == "/identity/conditionalAccess/namedLocations"


def test_truncated_pages_mark_envelope_truncated() -> None:
    fake = FakeGraphClient()
    pages = [[{"id": f"p{i}"}] for i in range(5)]
    fake.register_list("/identity/conditionalAccess/namedLocations", paginated(*pages))

    op = get_operation("ca_named_locations")
    result = fake.get_list_result(
        "/identity/conditionalAccess/namedLocations",
        max_pages=2,
    )
    assert result.truncated is True
    assert len(result.items) == 2

    # Register only 3 pages and monkeypatch operation max_pages by using get_list_result
    env = collect_graph_operation(fake, "ca_named_locations")
    assert env.health is EvidenceHealth.OK

    many = [[{"id": f"x{i}"}] for i in range(op.max_pages + 3)]
    fake2 = FakeGraphClient()
    fake2.register_list("/identity/conditionalAccess/namedLocations", paginated(*many))
    env2 = collect_graph_operation(fake2, "ca_named_locations")
    assert env2.health is EvidenceHealth.TRUNCATED
    assert env2.metadata.pagination.truncated is True


def test_403_maps_to_denied() -> None:
    fake = FakeGraphClient()
    fake.register_list("/applications", error(403, "Forbidden"))
    env = collect_graph_operation(fake, "applications")
    assert env.health is EvidenceHealth.DENIED
    assert "403" in env.reason or "Forbidden" in env.reason


def test_404_maps_to_unavailable() -> None:
    fake = FakeGraphClient()
    fake.register_get("/policies/crossTenantAccessPolicy", error(404, "Not found"))
    env = collect_graph_operation(fake, "cross_tenant_access_policy")
    assert env.health is EvidenceHealth.UNAVAILABLE


def test_unsupported_cloud_for_intune_on_china() -> None:
    fake = FakeGraphClient(cloud=CloudEnvironment.CHINA)
    fake.register_list("/deviceManagement/deviceCompliancePolicies", ok({"value": []}))
    env = collect_graph_operation(fake, "intune_compliance_policies")
    assert env.health is EvidenceHealth.UNSUPPORTED
    assert "china" in env.reason


def test_beta_blocked_without_preview() -> None:
    client = GraphClient(_auth(), allow_preview=False, sleep=lambda _s: None)
    client._http = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"value": []}, request=request)
        )
    )
    with pytest.raises(GraphError) as exc:
        client.get("https://graph.microsoft.com/beta/foo")
    assert exc.value.status_code == 400
    assert "beta" in str(exc.value).lower()
    client.close()


def test_beta_allowed_with_preview_flag() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={"ok": True}, request=request)

    client = GraphClient(_auth(), allow_preview=True, sleep=lambda _s: None)
    client._http = httpx.Client(transport=httpx.MockTransport(handler))
    data = client.get("https://graph.microsoft.com/beta/previewResource")
    assert data["ok"] is True
    assert any("/beta/" in url for url in seen)
    client.close()


def test_graph_client_uses_gov_base_and_scope() -> None:
    client = GraphClient(_auth(), cloud=CloudEnvironment.US_GOV, sleep=lambda _s: None)
    assert client.base_url == "https://graph.microsoft.us/v1.0"
    assert client.graph_scope == "https://graph.microsoft.us/.default"
    client.close()


def test_429_retries_then_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(
            429,
            headers={"Retry-After": "0"},
            json={"error": {"code": "TooManyRequests", "message": "slow down"}},
            request=request,
        )

    client = GraphClient(_auth(), max_retries=2, sleep=sleeps.append)
    client._http = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(GraphError) as exc:
        client.get("/subscribedSkus")
    assert exc.value.status_code == 429
    assert calls["n"] == 3  # initial + 2 retries
    assert sleeps  # backoff invoked
    client.close()


def test_expired_token_refreshes_once() -> None:
    tokens = {"n": 0}
    cred = MagicMock()

    def get_token(_scope: str) -> _FakeToken:
        tokens["n"] += 1
        return _FakeToken()

    cred.get_token.side_effect = get_token
    auth = AuthContext(mode=AuthMode.CLIENT_SECRET, tenant_id="t1", credential=cred)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(
                401,
                json={"error": {"code": "InvalidAuthenticationToken", "message": "expired"}},
                request=request,
            )
        return httpx.Response(200, json={"value": [{"id": "1"}]}, request=request)

    client = GraphClient(auth, sleep=lambda _s: None)
    client._http = httpx.Client(transport=httpx.MockTransport(handler))
    data = client.get("/subscribedSkus")
    assert data["value"][0]["id"] == "1"
    assert tokens["n"] == 2
    client.close()


def test_expired_token_second_401_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"error": {"code": "InvalidAuthenticationToken", "message": "expired"}},
            request=request,
        )

    client = GraphClient(_auth(), sleep=lambda _s: None)
    client._http = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(GraphError) as exc:
        client.get("/subscribedSkus")
    assert exc.value.status_code == 401
    client.close()


def test_write_post_not_allowlisted() -> None:
    client = GraphClient(_auth(), sleep=lambda _s: None)
    client._http = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={}, request=request))
    )
    with pytest.raises(GraphError) as exc:
        client.post("/users", json_body={"displayName": "nope"})
    assert exc.value.status_code == 405
    client.close()


def test_mde_health_summary_from_fake() -> None:
    fake = FakeMdeClient()
    fake.register_get(
        "/machines",
        ok(
            {
                "value": [
                    {"id": "m1", "healthStatus": "Active"},
                    {"id": "m2", "healthStatus": "ImpairedCommunication"},
                    {"id": "m3", "healthStatus": "Active"},
                ]
            }
        ),
    )
    summary = collect_mde_health_summary(_auth(), client=fake)
    assert summary["machines_sampled"] == 3
    assert summary["active_healthy"] == 2
    assert summary["impaired_communication"] == 1

    env = collect_mde_health_evidence(_auth(), client=fake)
    assert env.health is EvidenceHealth.OK


def test_mde_health_unsupported_china() -> None:
    env = collect_mde_health_evidence(_auth(), cloud=CloudEnvironment.CHINA)
    assert env.health is EvidenceHealth.UNSUPPORTED


def test_selective_arm_evidence_happy() -> None:
    fake = FakeArmClient()
    wid = (
        "subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws"
    )
    fake.register_get(
        f"{wid}/providers/Microsoft.SecurityInsights/alertRules",
        ok({"value": [{"name": "r1"}]}),
    )
    fake.register_get(
        f"{wid}/providers/Microsoft.SecurityInsights/settings",
        ok({"value": [{"name": "EntityAnalytics"}]}),
    )
    fake.register_get(
        "subscriptions/sub/providers/Microsoft.Security/pricings",
        ok({"value": [{"name": "VirtualMachines"}]}),
    )
    envs = collect_selective_arm_evidence(
        _auth(),
        workspace_resource_id=f"/{wid}",
        subscription_id="sub",
        client=fake,
    )
    assert set(SELECTIVE_ARM_OPERATIONS) <= set(envs)
    assert envs["arm_sentinel_alert_rules"].health is EvidenceHealth.OK
    assert envs["arm_defender_for_cloud_pricings"].health is EvidenceHealth.OK


def test_selective_arm_unsupported_china() -> None:
    envs = collect_selective_arm_evidence(
        _auth(),
        workspace_resource_id="/subscriptions/s/resourceGroups/r/providers/"
        "Microsoft.OperationalInsights/workspaces/w",
        cloud=CloudEnvironment.CHINA,
    )
    assert all(e.health is EvidenceHealth.UNSUPPORTED for e in envs.values())


def test_selective_arm_403_denied() -> None:
    fake = FakeArmClient()
    fake.register_get(
        "subscriptions/sub/providers/Microsoft.Security/pricings",
        error(403, "Forbidden"),
    )
    envs = collect_selective_arm_evidence(
        _auth(),
        subscription_id="sub",
        client=fake,
    )
    assert envs["arm_defender_for_cloud_pricings"].health is EvidenceHealth.DENIED


def test_auth_failure_on_token_maps_denied() -> None:
    cred = MagicMock()
    cred.get_token.side_effect = RuntimeError("AADSTS700016: app not found")
    auth = AuthContext(mode=AuthMode.CLIENT_SECRET, tenant_id="t1", credential=cred)
    client = GraphClient(auth, sleep=lambda _s: None)
    client._http = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={}, request=request))
    )
    with pytest.raises(AuthError):
        client.get("/organization")
    client.close()


def test_malformed_list_payload_skips_non_objects() -> None:
    fake = FakeGraphClient()
    fake.register_list(
        "/applications",
        ok({"value": [{"id": "ok"}, "bad", 3, None]}),
    )
    items = fake.get_list("/applications")
    assert items == [{"id": "ok"}]


def test_no_generic_cspm_operations() -> None:
    banned_fragments = (
        "virtualMachines",
        "storageAccounts",
        "sqlServers",
        "networkSecurityGroups",
        "Microsoft.Compute",
        "Microsoft.Network",
        "Microsoft.Storage",
    )
    for op in iter_operations():
        path = op.path.lower()
        for frag in banned_fragments:
            assert frag.lower() not in path
