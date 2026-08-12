"""Doctor graphPermissions check: granted app permissions vs the required tuple."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from licenselens.auth import REQUIRED_GRAPH_APP_PERMISSIONS, AuthContext, AuthMode
from licenselens.doctor import GRAPH_RESOURCE_APP_ID, DoctorCheck, run_doctor
from tests.fake_clients import FakeGraphClient, error, ok

CLIENT_ID = "client-app-1"
SP_ID = "sp-1"


class _FakeToken:
    token = "fake-token"


def _auth() -> AuthContext:
    cred = MagicMock()
    cred.get_token.return_value = _FakeToken()
    return AuthContext(
        mode=AuthMode.CLIENT_SECRET, tenant_id="t1", client_id=CLIENT_ID, credential=cred
    )


def _base_fake() -> FakeGraphClient:
    """Routes every live probe run_doctor performs; only servicePrincipal
    routes are left for each test to register."""
    fake = FakeGraphClient()
    fake.register_list(
        "/organization", ok({"value": [{"id": "t1", "displayName": "Contoso"}]})
    )
    fake.register_list("/subscribedSkus", ok({"value": []}))
    fake.register_list("/identity/conditionalAccess/policies", ok({"value": []}))
    fake.register_list("/roleManagement/directory/roleAssignments", ok({"value": []}))
    fake.register_get(
        "/security/secureScores", ok({"value": [{"id": "s1", "controlScores": []}]})
    )
    return fake


def _granted(granted_permissions: list[str]) -> FakeGraphClient:
    fake = _base_fake()
    fake.register_get(
        f"/servicePrincipals(appId='{CLIENT_ID}')", ok({"id": SP_ID, "appId": CLIENT_ID})
    )
    fake.register_get(
        f"/servicePrincipals(appId='{GRAPH_RESOURCE_APP_ID}')",
        ok(
            {
                "id": "graph-sp",
                "appRoles": [
                    {"id": f"graph-role-{p}", "value": p} for p in granted_permissions
                ],
            }
        ),
    )
    fake.register_list(
        f"/servicePrincipals/{SP_ID}/appRoleAssignments",
        ok(
            {
                "value": [
                    {"id": f"assign-{p}", "appRoleId": f"graph-role-{p}"}
                    for p in granted_permissions
                ]
            }
        ),
    )
    return fake


def _check(report, name: str) -> DoctorCheck:
    matches = [c for c in report.checks if c.name == name]
    assert len(matches) == 1, f"expected exactly one {name!r} check, got {len(matches)}"
    return matches[0]


def _run(fake: FakeGraphClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("licenselens.doctor.GraphClient", lambda auth: fake)
    return run_doctor(_auth())


def test_graph_permissions_all_granted(monkeypatch: pytest.MonkeyPatch):
    report = _run(_granted(list(REQUIRED_GRAPH_APP_PERMISSIONS)), monkeypatch)
    row = _check(report, "graphPermissions")
    assert row.ok is True
    assert row.optional is True
    assert "granted" in row.detail
    assert row.fix == ""


def test_graph_permissions_reports_missing(monkeypatch: pytest.MonkeyPatch):
    granted = list(REQUIRED_GRAPH_APP_PERMISSIONS)[:5]
    missing = list(REQUIRED_GRAPH_APP_PERMISSIONS)[5:]
    assert len(missing) == 2
    report = _run(_granted(granted), monkeypatch)
    row = _check(report, "graphPermissions")
    assert row.ok is False
    assert row.optional is True
    for perm in missing:
        assert perm in row.detail
        assert perm in row.fix
    assert "Grant" in row.fix and "re-consent" in row.fix
    assert report.ready is True


def test_graph_permissions_denied_is_optional_and_ready(monkeypatch: pytest.MonkeyPatch):
    fake = _base_fake()
    fake.register_get(
        f"/servicePrincipals(appId='{CLIENT_ID}')",
        error(403, "Authorization_RequestDenied"),
    )
    report = _run(fake, monkeypatch)
    row = _check(report, "graphPermissions")
    assert row.ok is False
    assert row.optional is True
    assert "cannot verify granted permissions" in row.detail
    assert report.ready is True
