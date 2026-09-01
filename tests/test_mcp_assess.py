"""Phase 1 MCP: pure posture-assessment layer (no MCP SDK required)."""

from __future__ import annotations

from datetime import UTC, datetime

from licenselens.auth import AuthContext, AuthMode
from licenselens.engine.runner import run_scan
from licenselens.models import ScanResult

FROZEN_TIME = datetime(2026, 1, 1, tzinfo=UTC)


def _direct_demo_payload() -> dict:
    result = run_scan(AuthContext(mode=AuthMode.DRY_RUN), dry_run=True, scanned_at=FROZEN_TIME)
    return result.model_dump(mode="json")


def test_demo_assess_returns_valid_scan_result():
    from licenselens.mcp_assess import run_assessment

    payload = run_assessment(scanned_at=FROZEN_TIME)
    validated = ScanResult.model_validate(payload)  # raises if not the locked contract
    assert validated.scan_mode == "dry_run"
    assert payload["tool"] == "security-license-lens"


def test_demo_payload_matches_direct_run_scan():
    from licenselens.mcp_assess import run_assessment

    assert run_assessment(scanned_at=FROZEN_TIME) == _direct_demo_payload()


def test_demo_frozen_anchors():
    from licenselens.mcp_assess import run_assessment

    payload = run_assessment(scanned_at=FROZEN_TIME)
    ids = [f["check_id"] for f in payload["findings"]]
    assert len(ids) == 166
    assert len(payload["owned_capabilities"]) == 25
    assert "id-ca-priv-gaps" in ids
    statuses: dict[str, int] = {}
    for f in payload["findings"]:
        statuses[f["status"]] = statuses.get(f["status"], 0) + 1
    assert statuses == {"gap": 40, "partial": 17, "skipped": 12, "ok": 91, "not_licensed": 6}
    assert payload["moves"] and payload["recommended_next_steps"]


def test_live_without_credentials_returns_structured_error(monkeypatch):
    from licenselens.mcp_assess import run_assessment

    for var in (
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_CLIENT_CERTIFICATE_PATH",
        "AZURE_CLIENT_CERT_THUMBPRINT",
    ):
        monkeypatch.delenv(var, raising=False)

    payload = run_assessment(live=True)  # must not raise
    assert set(payload) == {"error"}
    err = payload["error"]
    assert err["code"] == "auth_unavailable"
    assert "licenselens scan --live" in err["hint"]
    assert "AZURE_TENANT_ID" in err["hint"]


def test_live_device_auth_is_rejected_as_invalid_argument(monkeypatch):
    from licenselens.mcp_assess import run_assessment

    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    payload = run_assessment(live=True, auth="device")
    assert payload["error"]["code"] == "invalid_argument"


def test_unknown_workload_returns_invalid_argument():
    from licenselens.mcp_assess import run_assessment

    payload = run_assessment(workloads=["nope"])
    assert payload["error"]["code"] == "invalid_argument"


def test_live_auth_config_error_maps_to_envelope(monkeypatch):
    """Env creds half-present -> AuthConfigError -> envelope, not a crash."""
    from licenselens.mcp_assess import run_assessment

    monkeypatch.setenv("AZURE_TENANT_ID", "tid")
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    payload = run_assessment(live=True, auth="client_secret")
    assert payload["error"]["code"] == "auth_config"
