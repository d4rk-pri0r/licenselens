"""Golden-tenant parity test (B9 / Phase-4 task 23).

Replays ``tests/fixtures/golden-tenant.json`` through the LIVE collectors
(FakeGraphClient + FakeArmClient + FakeMdeClient + a PowerShell-bridge
ProcessRunner double) and asserts the resulting report's finding counts and
statuses match the pinned golden expectations.

The fixture is a synthetic tenant (no real PII; clearly-fake GUIDs/names) that
exercises the t2/t3/t4 fixes end-to-end:

- t2: subscribedSkus carries real ``servicePlanId`` GUIDs, so capability
  resolution unlocks entitlements (``you_own`` > 0).
- t3: a CA policy whose ``grantControls.operator`` is ``OR`` with
  ``["mfa", "passwordChange"]`` must NOT count as MFA-enforcing, and a legacy
  block policy with an undocumented break-glass exclusion must report partial.
- t4: a privileged service principal with no credentials is flagged dormant,
  and standing GA assignments without full PIM coverage stay a gap.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from licenselens.auth import AuthContext, AuthMode
from licenselens.engine.runner import run_scan
from licenselens.models import FindingStatus
from licenselens.report.html import write_html_report
from licenselens.report.json_report import write_json_report
from licenselens.report.markdown import write_markdown_report
from tests.fake_clients import build_replay_clients, wire_golden_seams

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "golden-tenant.json"

GOLDEN_TOTAL_FINDINGS = 166
GOLDEN_COUNTS_BY_STATUS = {
    "gap": 39,
    "not_licensed": 6,
    "ok": 90,
    "partial": 19,
    "skipped": 12,
}
GOLDEN_CHECK_STATUSES = {
    "id-ca-mfa-all-users": FindingStatus.GAP,
    "id-ca-legacy-auth-block": FindingStatus.PARTIAL,
    "id-ca-priv-gaps": FindingStatus.GAP,
    "id-dormant-privileged": FindingStatus.GAP,
    "id-pim-no-permanent-privileged": FindingStatus.GAP,
    "id-pim-unused": FindingStatus.PARTIAL,
}


def _load_fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _run_golden_scan(monkeypatch: pytest.MonkeyPatch):
    payload = _load_fixture()
    replay = build_replay_clients(payload)
    wire_golden_seams(monkeypatch, replay)

    auth = AuthContext(mode=AuthMode.CLIENT_SECRET, tenant_id=payload["tenant"]["id"])
    return run_scan(
        auth,
        dry_run=False,
        workspace_resource_id=payload["tenant"]["workspace_resource_id"],
        allow_email_proxy=True,
    )


def test_golden_tenant_replays_live_collectors(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _run_golden_scan(monkeypatch)

    assert result.scan_mode == "live"
    assert result.tenant_display_name == "GoldenCo"

    assert len(result.findings) == GOLDEN_TOTAL_FINDINGS
    assert result.counts_by_status == GOLDEN_COUNTS_BY_STATUS

    by_id = {finding.check_id: finding for finding in result.findings}
    for check_id, expected_status in GOLDEN_CHECK_STATUSES.items():
        assert by_id[check_id].status is expected_status, (
            f"{check_id}: expected {expected_status.value}, "
            f"got {by_id[check_id].status.value}"
        )

    assert result.capability_rollup.you_own > 0


def test_golden_tenant_renders_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = _run_golden_scan(monkeypatch)

    html = write_html_report(result, tmp_path / "report.html")
    js = write_json_report(result, tmp_path / "report.json")
    md = write_markdown_report(result, tmp_path / "report.md")

    html_text = html.read_text(encoding="utf-8")
    assert "GoldenCo" in html_text
    assert js.read_text(encoding="utf-8").startswith("{")
    assert md.is_file()


def test_golden_fixture_shape() -> None:
    payload = _load_fixture()

    assert payload["version"] == 1
    assert payload["tenant"]["display_name"] == "GoldenCo"
    for section in ("graph", "arm", "mde", "powershell"):
        assert section in payload, f"fixture missing {section!r} section"

    ca = payload["graph"]["list"]["/identity/conditionalAccess/policies"]["value"]
    or_grant = next(p for p in ca if p["id"] == "golden-or-grant")
    assert or_grant["grantControls"]["operator"] == "OR"
    assert set(or_grant["grantControls"]["builtInControls"]) == {"mfa", "passwordChange"}

    sku = payload["graph"]["list"]["/subscribedSkus"]["value"][0]
    plan_ids = {sp["servicePlanId"] for sp in sku["servicePlans"]}
    assert "eec0eb4f-6444-4f95-aba0-50c24d67f998" in plan_ids  # AAD_PREMIUM_P2
