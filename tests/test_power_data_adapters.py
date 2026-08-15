"""Contract tests for Power Platform / Power BI / Purview PowerShell adapters."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

import pytest

from licenselens.collectors.contracts import EvidenceHealth, EvidenceKey
from licenselens.collectors.power_data import (
    PowerDataCollectOptions,
    bundle_to_evidence,
    collect_power_data_bundle,
)
from licenselens.collectors.power_data_demo import DEMO_FIXTURES, DEMO_PBI_TENANT_PAYLOAD
from licenselens.collectors.power_data_fixtures import (
    DEMO_PBI_MODULE_DRIFT_PAYLOAD,
    DEMO_PP_ENVIRONMENTS_PAYLOAD,
    DEMO_PURVIEW_ABSENT_DLP_PAYLOAD,
)
from licenselens.collectors.power_data_models import (
    COVERAGE_SURFACE_MAP,
    MANUAL_PORTAL_POLICY_IDS,
    PBI_TENANT_ADAPTER,
    POWER_DATA_ADAPTERS,
    PP_DLP_ADAPTER,
    PP_ENVIRONMENTS_ADAPTER,
    PP_ISOLATION_ADAPTER,
    PP_TENANT_ADAPTER,
    PURVIEW_ADAPTER,
    PURVIEW_SURFACES,
    PolicyKind,
    PowerDataBundle,
    SurfaceStatus,
)
from licenselens.collectors.power_data_normalize import (
    PowerDataPayloadParseError,
    coverage_evidence_for_bundle,
    normalize_adapter_payload,
    unavailable_payload,
)
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

_BANNED_WRITE: Final[tuple[str, ...]] = (
    "Set-TenantSettings",
    "Set-AdminPowerAppEnvironment",
    "New-DlpPolicy",
    "Remove-DlpPolicy",
    "Set-DlpPolicy",
    "Set-PowerAppTenantIsolationPolicy",
    "Set-PowerBITenantSetting",
    "New-Label",
    "Set-Label",
    "Remove-Label",
    "Set-RetentionCompliancePolicy",
    "New-RetentionCompliancePolicy",
    "Remove-RetentionCompliancePolicy",
    "Set-DlpCompliancePolicy",
)


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


def _err(code: str, message: str, *, adapter: str = PP_TENANT_ADAPTER) -> bytes:
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


def test_allowlisted_adapters_include_power_data_surfaces() -> None:
    adapters = list_allowlisted_adapters(ROOT)
    for name in POWER_DATA_ADAPTERS:
        assert name in adapters
        path = resolve_adapter_path(name, module_root=ROOT)
        assert path.is_file()
        text = path.read_text(encoding="utf-8")
        assert "Invoke-LicenseLensAdapter" in text
        for banned in _BANNED_WRITE:
            assert banned not in text


def test_normalize_multi_environment_matrix() -> None:
    payload = normalize_adapter_payload(
        DEMO_PP_ENVIRONMENTS_PAYLOAD,
        adapter=PP_ENVIRONMENTS_ADAPTER,
    )
    envs = payload.surfaces["environments"]
    assert envs.status is SurfaceStatus.OK
    assert envs.raw_count == 3
    kinds = {item.kind for item in envs.items}
    assert PolicyKind.DEFAULT in kinds
    assert PolicyKind.CUSTOM in kinds
    no_dv = [i for i in envs.items if i.properties.get("HasDataverse") is False]
    assert len(no_dv) == 1
    assert no_dv[0].name == "Sandbox No Dataverse"


def test_every_power_coverage_row_has_explicit_state() -> None:
    adapters = {
        name: normalize_adapter_payload(payload, adapter=name)
        for name, payload in DEMO_FIXTURES.items()
    }
    bundle = PowerDataBundle(adapters=adapters)
    rows = coverage_evidence_for_bundle(bundle)
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
        if row.policy_id in MANUAL_PORTAL_POLICY_IDS:
            assert row.portal_only is True
            assert row.status is SurfaceStatus.UNSUPPORTED


def test_portal_only_and_manual_rows_explicit() -> None:
    payload = normalize_adapter_payload(
        DEMO_FIXTURES[PP_TENANT_ADAPTER],
        adapter=PP_TENANT_ADAPTER,
    )
    csp = payload.surfaces["content_security_policy"]
    allow = payload.surfaces["isolation_allowlist"]
    assert csp.status is SurfaceStatus.UNSUPPORTED
    assert csp.portal_only is True
    assert "portal-only" in csp.reason.lower() or "dataverse" in csp.reason.lower()
    assert allow.status is SurfaceStatus.UNSUPPORTED
    assert allow.portal_only is True


def test_absent_configuration_distinct_from_unreadable() -> None:
    absent = normalize_adapter_payload(
        DEMO_PURVIEW_ABSENT_DLP_PAYLOAD,
        adapter=PURVIEW_ADAPTER,
    )
    dlp = absent.surfaces["dlp_policies"]
    assert dlp.status is SurfaceStatus.OK
    assert dlp.raw_count == 0
    assert dlp.reason.startswith("absent")

    denied = normalize_adapter_payload(
        {
            "adapter": PURVIEW_ADAPTER,
            "surfaces": {
                "dlp_policies": {
                    "surface": "dlp_policies",
                    "status": "denied",
                    "reason": "Access denied",
                    "raw_count": 0,
                    "items": [],
                }
            },
        },
        adapter=PURVIEW_ADAPTER,
    )
    assert denied.surfaces["dlp_policies"].status is SurfaceStatus.DENIED


def test_purview_surfaces_include_retention_and_audit() -> None:
    payload = normalize_adapter_payload(
        DEMO_FIXTURES[PURVIEW_ADAPTER],
        adapter=PURVIEW_ADAPTER,
    )
    assert set(PURVIEW_SURFACES) <= set(payload.surfaces)
    assert payload.surfaces["retention_policies"].status is SurfaceStatus.OK
    assert payload.surfaces["audit_config"].items[0].enabled is True


def test_pbi_tenant_happy_settings() -> None:
    payload = normalize_adapter_payload(DEMO_PBI_TENANT_PAYLOAD, adapter=PBI_TENANT_ADAPTER)
    assert payload.surfaces["publish_to_web"].items[0].enabled is False
    assert payload.surfaces["resource_key_auth"].items[0].enabled is True
    assert payload.surfaces["sensitivity_labels"].status is SurfaceStatus.OK


def test_module_version_drift_pbi_unsupported() -> None:
    payload = normalize_adapter_payload(
        DEMO_PBI_MODULE_DRIFT_PAYLOAD,
        adapter=PBI_TENANT_ADAPTER,
    )
    for surface in payload.surfaces.values():
        assert surface.status is SurfaceStatus.UNSUPPORTED
        reason = surface.reason
        assert "module-version drift" in reason or "Get-PowerBITenantSetting" in reason


def test_normalize_rejects_malformed_surfaces() -> None:
    with pytest.raises(PowerDataPayloadParseError):
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
        for name in POWER_DATA_ADAPTERS
    ]
    runner = ScriptedRunner(results)
    bundle = collect_power_data_bundle(
        PowerDataCollectOptions(
            runner=runner,
            executable=Path("/usr/bin/pwsh"),
            fixture_by_adapter=DEMO_FIXTURES,
        )
    )
    assert set(bundle.adapters) == set(POWER_DATA_ADAPTERS)
    assert len(runner.calls) == len(POWER_DATA_ADAPTERS)
    assert all(call["shell"] is False for call in runner.calls)
    evidence = bundle_to_evidence(bundle)
    assert evidence["power_data_direct"] is True
    assert evidence["proxy"] is False
    assert len(evidence["power_data_coverage"]) == len(COVERAGE_SURFACE_MAP)


def test_missing_module_maps_to_unavailable_typed_state() -> None:
    runner = ScriptedRunner(
        [
            BridgeProcessResult(
                0,
                _err(
                    "module_missing",
                    "module_missing: Microsoft.PowerApps.Administration.PowerShell",
                ),
                b"",
                False,
                False,
                False,
            )
        ]
    )
    bundle = collect_power_data_bundle(
        PowerDataCollectOptions(
            adapters=(PP_TENANT_ADAPTER,),
            runner=runner,
            executable=Path("/usr/bin/pwsh"),
        )
    )
    surface = bundle.adapters[PP_TENANT_ADAPTER].surfaces["adapter"]
    assert surface.status is SurfaceStatus.UNAVAILABLE
    assert "module" in surface.reason.lower()


def test_disconnected_session_maps_to_disconnected_or_unavailable() -> None:
    runner = ScriptedRunner(
        [
            BridgeProcessResult(
                0,
                _err(
                    "unavailable",
                    "disconnected: Power Platform admin session not connected",
                    adapter=PP_DLP_ADAPTER,
                ),
                b"",
                False,
                False,
                False,
            )
        ]
    )
    bundle = collect_power_data_bundle(
        PowerDataCollectOptions(
            adapters=(PP_DLP_ADAPTER,),
            runner=runner,
            executable=Path("/usr/bin/pwsh"),
        )
    )
    status = bundle.adapters[PP_DLP_ADAPTER].surfaces["adapter"].status
    assert status in {SurfaceStatus.DISCONNECTED, SurfaceStatus.UNAVAILABLE}


def test_security_payload_adapter_injection_never_spawns() -> None:
    runner = ScriptedRunner(
        [
            BridgeProcessResult(
                0,
                _ok(DEMO_FIXTURES[PP_TENANT_ADAPTER], adapter=PP_TENANT_ADAPTER),
                b"",
                False,
                False,
                False,
            )
        ]
    )
    envelope = invoke_powershell_adapter(
        BridgeInvokeRequest(
            adapter="pp_tenant; rm -rf /",
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
                _ok(DEMO_FIXTURES[PP_ISOLATION_ADAPTER], adapter=PP_ISOLATION_ADAPTER),
                b"boom",
                False,
                False,
                False,
            )
        ]
    )
    bundle = collect_power_data_bundle(
        PowerDataCollectOptions(
            adapters=(PP_ISOLATION_ADAPTER,),
            runner=runner,
            executable=Path("/usr/bin/pwsh"),
        )
    )
    assert bundle.adapters[PP_ISOLATION_ADAPTER].surfaces["adapter"].status is SurfaceStatus.ERROR


def test_unavailable_payload_helper() -> None:
    payload = unavailable_payload(
        "pp_tenant",
        reason="module_missing: Microsoft.PowerApps.Administration.PowerShell",
        status=SurfaceStatus.UNAVAILABLE,
    )
    assert payload.surfaces["adapter"].status is SurfaceStatus.UNAVAILABLE


def test_adapter_scripts_contain_only_get_read_verbs() -> None:
    for name in POWER_DATA_ADAPTERS:
        text = (ROOT / "adapters" / f"{name}.ps1").read_text(encoding="utf-8")
        for cmd in _BANNED_WRITE:
            assert cmd not in text, f"{name} contains write cmdlet {cmd}"
        # Live path uses Get-* / fixture_mode only (no Set-/New-/Remove- mutations).
        assert "Get-LicenseLensFixtureData" in text or "fixture" in text.lower()
