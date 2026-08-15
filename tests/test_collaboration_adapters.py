"""Contract tests for Teams / SharePoint-OneDrive PowerShell adapters."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

import pytest

from licenselens.collectors.collaboration import (
    CollaborationCollectOptions,
    bundle_to_evidence,
    collect_collaboration_bundle,
)
from licenselens.collectors.collaboration_demo import DEMO_FIXTURES, DEMO_TEAMS_MEETING_PAYLOAD
from licenselens.collectors.collaboration_models import (
    COLLABORATION_ADAPTERS,
    COVERAGE_SURFACE_MAP,
    SPO_ADAPTER,
    TEAMS_APPS_ADAPTER,
    TEAMS_MEETING_ADAPTER,
    CollaborationBundle,
    PolicyKind,
    SurfaceStatus,
)
from licenselens.collectors.collaboration_normalize import (
    CollaborationPayloadParseError,
    coverage_evidence_for_bundle,
    normalize_adapter_payload,
    unavailable_payload,
)
from licenselens.collectors.contracts import EvidenceHealth, EvidenceKey
from licenselens.collectors.powershell import (
    BRIDGE_PROTOCOL_VERSION,
    BridgeInvokeRequest,
    BridgeProcessResult,
    invoke_powershell_adapter,
    list_allowlisted_adapters,
    powershell_module_root,
    resolve_adapter_path,
)
from licenselens.schema_contracts import JsonValue

ROOT: Final = powershell_module_root()


class ScriptedRunner:
    def __init__(self, results: Sequence[BridgeProcessResult]) -> None:
        self._results = list(results)
        self.calls: list[dict[str, object]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: bytes,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
        cwd: Path | None,
        env: Mapping[str, str] | None,
    ) -> BridgeProcessResult:
        self.calls.append(
            {
                "argv": list(argv),
                "stdin": stdin,
                "shell": False,
                "cwd": cwd,
            }
        )
        if not self._results:
            msg = "no scripted results left"
            raise AssertionError(msg)
        return self._results.pop(0)


def _ok(data: Mapping[str, JsonValue], *, adapter: str) -> bytes:
    body: dict[str, JsonValue] = {
        "protocol_version": BRIDGE_PROTOCOL_VERSION,
        "ok": True,
        "adapter": adapter,
        "module_version": "0.1.0",
        "cloud": "public",
        "data": dict(data),
        "error": None,
    }
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _err(code: str, message: str, *, adapter: str = TEAMS_MEETING_ADAPTER) -> bytes:
    body: dict[str, JsonValue] = {
        "protocol_version": BRIDGE_PROTOCOL_VERSION,
        "ok": False,
        "adapter": adapter,
        "module_version": "0.1.0",
        "cloud": "public",
        "data": None,
        "error": {"code": code, "message": message},
    }
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def test_allowlisted_adapters_include_collaboration_surfaces() -> None:
    # Given: checked-in adapter tree
    adapters = list_allowlisted_adapters(ROOT)

    # When/Then: every collaboration adapter resolves and is read-only
    for name in COLLABORATION_ADAPTERS:
        assert name in adapters
        path = resolve_adapter_path(name, module_root=ROOT)
        assert path.is_file()
        text = path.read_text(encoding="utf-8")
        assert "Invoke-LicenseLensAdapter" in text
        for banned in (
            "Set-SPOTenant",
            "Set-CsTeamsMeetingPolicy",
            "Grant-CsTeamsMeetingPolicy",
            "Set-CsTenantFederationConfiguration",
            "Set-CsTeamsClientConfiguration",
            "Set-CsTeamsAppPermissionPolicy",
            "New-CsTeamsMeetingPolicy",
            "Remove-CsTeamsMeetingPolicy",
        ):
            assert banned not in text


def test_normalize_global_custom_meeting_matrix() -> None:
    # Given: fixture with compliant Global + weaker custom meeting policy
    payload = normalize_adapter_payload(
        DEMO_TEAMS_MEETING_PAYLOAD,
        adapter=TEAMS_MEETING_ADAPTER,
    )

    # When: policies are listed by kind
    meeting = payload.surfaces["meeting_policies"]
    kinds = {item.kind for item in meeting.items}
    customs = [item for item in meeting.items if item.kind is PolicyKind.CUSTOM]
    globals_ = [item for item in meeting.items if item.kind is PolicyKind.DEFAULT]

    # Then: custom is visible alongside global (cannot be hidden by compliant default)
    assert meeting.status is SurfaceStatus.OK
    assert PolicyKind.DEFAULT in kinds
    assert PolicyKind.CUSTOM in kinds
    assert globals_[0].properties.get("AllowCloudRecording") is False
    assert customs[0].properties.get("AllowCloudRecording") is True
    assert customs[0].assignments


def test_bundle_custom_policies_not_hidden_by_global() -> None:
    adapters = {
        name: normalize_adapter_payload(payload, adapter=name)
        for name, payload in DEMO_FIXTURES.items()
    }
    bundle = CollaborationBundle(adapters=adapters)

    assert bundle.custom_policies_visible("meeting_policies") is True
    customs = bundle.policies_for_surface("meeting_policies", kind=PolicyKind.CUSTOM)
    assert len(customs) == 1
    assert customs[0].name == "ExecRecording"


def test_every_collaboration_coverage_row_has_explicit_state() -> None:
    adapters = {
        name: normalize_adapter_payload(payload, adapter=name)
        for name, payload in DEMO_FIXTURES.items()
    }
    bundle = CollaborationBundle(adapters=adapters)
    rows = coverage_evidence_for_bundle(bundle)

    # Then: every pinned SharePoint/Teams policy_id is represented
    assert {row.policy_id for row in rows} == set(COVERAGE_SURFACE_MAP)
    for row in rows:
        assert row.status in {
            SurfaceStatus.OK,
            SurfaceStatus.DENIED,
            SurfaceStatus.UNAVAILABLE,
            SurfaceStatus.UNSUPPORTED,
            SurfaceStatus.ERROR,
            SurfaceStatus.DISCONNECTED,
        }
        assert row.adapter
        assert row.surface


def test_normalize_rejects_malformed_surfaces() -> None:
    with pytest.raises(CollaborationPayloadParseError):
        normalize_adapter_payload({"adapter": "x", "surfaces": []}, adapter="x")


def test_collect_bundle_fixture_mode_via_scripted_runner() -> None:
    results = [
        BridgeProcessResult(
            0,
            _ok(DEMO_FIXTURES[name], adapter=name),
            b"",
            False,
            False,
            False,
        )
        for name in COLLABORATION_ADAPTERS
    ]
    runner = ScriptedRunner(results)

    bundle = collect_collaboration_bundle(
        CollaborationCollectOptions(
            runner=runner,
            executable=Path("/usr/bin/pwsh"),
            fixture_by_adapter=DEMO_FIXTURES,
        )
    )

    assert set(bundle.adapters) == set(COLLABORATION_ADAPTERS)
    assert len(runner.calls) == len(COLLABORATION_ADAPTERS)
    assert all(call["shell"] is False for call in runner.calls)
    evidence = bundle_to_evidence(bundle)
    assert evidence["collaboration_direct"] is True
    assert evidence["proxy"] is False
    assert len(evidence["collaboration_coverage"]) == len(COVERAGE_SURFACE_MAP)


def test_missing_module_maps_to_unavailable_typed_state() -> None:
    runner = ScriptedRunner(
        [
            BridgeProcessResult(
                0,
                _err("module_missing", "module_missing: MicrosoftTeams"),
                b"",
                False,
                False,
                False,
            )
        ]
    )
    bundle = collect_collaboration_bundle(
        CollaborationCollectOptions(
            adapters=(TEAMS_MEETING_ADAPTER,),
            runner=runner,
            executable=Path("/usr/bin/pwsh"),
        )
    )
    payload = bundle.adapters[TEAMS_MEETING_ADAPTER]
    surface = payload.surfaces["adapter"]
    assert surface.status is SurfaceStatus.UNAVAILABLE
    assert "module" in surface.reason.lower()


def test_disconnected_session_maps_to_disconnected_or_unavailable() -> None:
    runner = ScriptedRunner(
        [
            BridgeProcessResult(
                0,
                _err(
                    "unavailable",
                    "disconnected: Microsoft Teams session not connected",
                ),
                b"",
                False,
                False,
                False,
            )
        ]
    )
    bundle = collect_collaboration_bundle(
        CollaborationCollectOptions(
            adapters=(TEAMS_MEETING_ADAPTER,),
            runner=runner,
            executable=Path("/usr/bin/pwsh"),
        )
    )
    status = bundle.adapters[TEAMS_MEETING_ADAPTER].surfaces["adapter"].status
    assert status in {SurfaceStatus.DISCONNECTED, SurfaceStatus.UNAVAILABLE}


def test_partial_admin_access_preserves_other_ok_surfaces() -> None:
    partial: dict[str, JsonValue] = {
        "adapter": TEAMS_MEETING_ADAPTER,
        "module": "MicrosoftTeams",
        "collection": "teams_meeting",
        "surfaces": {
            "meeting_policies": {
                "surface": "meeting_policies",
                "status": "ok",
                "reason": "",
                "raw_count": 1,
                "items": [
                    {
                        "name": "Global",
                        "kind": "default",
                        "enabled": True,
                        "properties": {"AllowCloudRecording": False},
                        "assignments": ["All"],
                    }
                ],
            },
            "broadcast_policies": {
                "surface": "broadcast_policies",
                "status": "denied",
                "reason": "Access denied",
                "raw_count": 0,
                "items": [],
            },
        },
    }
    payload = normalize_adapter_payload(partial, adapter=TEAMS_MEETING_ADAPTER)
    assert payload.surfaces["meeting_policies"].status is SurfaceStatus.OK
    assert payload.surfaces["broadcast_policies"].status is SurfaceStatus.DENIED
    bundle = CollaborationBundle(adapters={TEAMS_MEETING_ADAPTER: payload})
    status, reason = bundle.coverage_row_state("MS.TEAMS.1.7v2")
    assert status is SurfaceStatus.DENIED
    assert "denied" in reason.lower() or reason == "Access denied"


def test_unsupported_v2_teams_app_settings_explicit() -> None:
    payload = normalize_adapter_payload(
        DEMO_FIXTURES[TEAMS_APPS_ADAPTER],
        adapter=TEAMS_APPS_ADAPTER,
    )
    v2 = payload.surfaces["app_settings_v2"]
    assert v2.status is SurfaceStatus.UNSUPPORTED
    assert "Get-M365UnifiedTenantSettings" in v2.reason
    assert v2.national_cloud_limited is True
    # Legacy app permission policies remain readable
    assert payload.surfaces["app_permission_policies"].status is SurfaceStatus.OK
    kinds = {item.kind for item in payload.surfaces["app_permission_policies"].items}
    assert PolicyKind.CUSTOM in kinds


def test_security_payload_adapter_injection_never_spawns() -> None:
    runner = ScriptedRunner(
        [
            BridgeProcessResult(
                0,
                _ok(DEMO_TEAMS_MEETING_PAYLOAD, adapter=TEAMS_MEETING_ADAPTER),
                b"",
                False,
                False,
                False,
            )
        ]
    )
    envelope = invoke_powershell_adapter(
        BridgeInvokeRequest(
            adapter="teams_meeting; rm -rf /",
            evidence_key=EvidenceKey("ps.bad"),
        ),
        runner=runner,
        executable=Path("/usr/bin/pwsh"),
    )
    assert envelope.health is EvidenceHealth.ERROR
    assert runner.calls == []


def test_misleading_success_nonzero_exit_not_trusted() -> None:
    runner = ScriptedRunner(
        [
            BridgeProcessResult(
                9,
                _ok(DEMO_TEAMS_MEETING_PAYLOAD, adapter=TEAMS_MEETING_ADAPTER),
                b"boom",
                False,
                False,
                False,
            )
        ]
    )
    bundle = collect_collaboration_bundle(
        CollaborationCollectOptions(
            adapters=(TEAMS_MEETING_ADAPTER,),
            runner=runner,
            executable=Path("/usr/bin/pwsh"),
        )
    )
    assert bundle.adapters[TEAMS_MEETING_ADAPTER].surfaces["adapter"].status is SurfaceStatus.ERROR


def test_national_cloud_limited_surfaces_flagged() -> None:
    payload = normalize_adapter_payload(
        DEMO_FIXTURES["teams_federation"],
        adapter="teams_federation",
    )
    unmanaged = payload.surfaces["unmanaged_users"]
    assert unmanaged.national_cloud_limited is True


def test_spo_tenant_surfaces_cover_sharing_matrix() -> None:
    payload = normalize_adapter_payload(DEMO_FIXTURES[SPO_ADAPTER], adapter=SPO_ADAPTER)
    expected = {
        "sharing_capability",
        "onedrive_sharing",
        "domain_restrictions",
        "default_link",
        "anyone_link_expiration",
        "anyone_link_permissions",
        "reauth_days",
    }
    assert expected <= set(payload.surfaces)
    assert all(s.status is SurfaceStatus.OK for s in payload.surfaces.values())


def test_unavailable_payload_helper() -> None:
    payload = unavailable_payload(
        "spo_tenant",
        reason="module_missing: Microsoft.Online.SharePoint.PowerShell",
        status=SurfaceStatus.UNAVAILABLE,
    )
    assert payload.surfaces["adapter"].status is SurfaceStatus.UNAVAILABLE


def test_adapter_scripts_contain_only_get_read_verbs() -> None:
    banned = (
        "Set-SPOTenant",
        "Set-CsTeamsMeetingPolicy",
        "Grant-CsTeamsMeetingPolicy",
        "Set-CsTenantFederationConfiguration",
        "Set-CsTeamsClientConfiguration",
        "Set-CsTeamsAppPermissionPolicy",
        "Set-CsExternalAccessPolicy",
        "New-CsTeamsMeetingPolicy",
        "Remove-CsTeamsMeetingPolicy",
        "Remove-CsTeamsAppPermissionPolicy",
    )
    for name in COLLABORATION_ADAPTERS:
        text = (ROOT / "adapters" / f"{name}.ps1").read_text(encoding="utf-8")
        for cmd in banned:
            assert cmd not in text, f"{name} contains write cmdlet {cmd}"
