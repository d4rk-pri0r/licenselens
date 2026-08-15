"""Contract tests for Exchange Online / SCC PowerShell adapters and normalization."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

import pytest

from licenselens.collectors.contracts import EvidenceHealth, EvidenceKey
from licenselens.collectors.exchange import (
    DEMO_THREAT_PAYLOAD,
    ExchangeCollectOptions,
    bundle_to_evidence,
    collect_exchange_bundle,
    demo_exchange_evidence,
)
from licenselens.collectors.exchange_models import (
    EXCHANGE_ADAPTERS,
    THREAT_ADAPTER,
    ExchangeBundle,
    PolicyKind,
    SurfaceStatus,
)
from licenselens.collectors.exchange_normalize import (
    ExchangePayloadParseError,
    normalize_adapter_payload,
    unavailable_payload,
)
from licenselens.collectors.powershell import (
    BRIDGE_PROTOCOL_VERSION,
    BridgeProcessResult,
    invoke_powershell_adapter,
    list_allowlisted_adapters,
    powershell_module_root,
    resolve_adapter_path,
)
from licenselens.evaluators.defender import evaluate_mdo_p2_policies
from licenselens.models import CheckDefinition, FindingStatus, Workload
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


def _ok(data: Mapping[str, JsonValue], *, adapter: str = THREAT_ADAPTER) -> bytes:
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


def _err(code: str, message: str, *, adapter: str = THREAT_ADAPTER) -> bytes:
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


def _check() -> CheckDefinition:
    return CheckDefinition(
        id="mdo-p2-policies-default",
        title="mdo",
        workload=Workload.DEFENDER,
    )


def test_allowlisted_adapters_include_exchange_and_scc_surfaces() -> None:
    # Given: checked-in adapter tree
    adapters = list_allowlisted_adapters(ROOT)

    # When/Then: every Exchange/SCC adapter name resolves under adapters/
    for name in EXCHANGE_ADAPTERS:
        assert name in adapters
        path = resolve_adapter_path(name, module_root=ROOT)
        assert path.is_file()
        text = path.read_text(encoding="utf-8")
        assert "Invoke-LicenseLensAdapter" in text
        for banned in (
            "New-Mailbox",
            "Set-MalwareFilterPolicy",
            "Set-SafeLinksPolicy",
            "Set-AntiPhishPolicy",
            "Remove-TransportRule",
        ):
            assert banned not in text


def test_normalize_happy_threat_fixture_schema() -> None:
    # Given: sanitized threat-policy fixture
    # When: normalized at the boundary
    payload = normalize_adapter_payload(DEMO_THREAT_PAYLOAD, adapter=THREAT_ADAPTER)

    # Then: typed surfaces enumerate default/custom/preset policies
    assert payload.adapter == THREAT_ADAPTER
    assert payload.proxy is False
    links = payload.surfaces["safe_links"]
    assert links.status is SurfaceStatus.OK
    kinds = {item.kind for item in links.items}
    assert PolicyKind.PRESET_STANDARD in kinds
    assert PolicyKind.CUSTOM in kinds
    assert any(item.assignments for item in links.items)


def test_normalize_rejects_malformed_surfaces() -> None:
    with pytest.raises(ExchangePayloadParseError):
        normalize_adapter_payload({"adapter": "x", "surfaces": []}, adapter="x")


def test_collect_bundle_fixture_mode_via_scripted_runner() -> None:
    # Given: scripted OK responses for all adapters using fixture payloads
    results = [
        BridgeProcessResult(0, _ok(DEMO_THREAT_PAYLOAD, adapter=name), b"", False, False, False)
        for name in EXCHANGE_ADAPTERS
    ]
    runner = ScriptedRunner(results)

    # When: bundle is collected without live EXO modules
    bundle = collect_exchange_bundle(
        ExchangeCollectOptions(
            runner=runner,
            executable=Path("/usr/bin/pwsh"),
            fixture_by_adapter={name: DEMO_THREAT_PAYLOAD for name in EXCHANGE_ADAPTERS},
        )
    )

    # Then: all adapters present and threat policies usable
    assert set(bundle.adapters) == set(EXCHANGE_ADAPTERS)
    assert bundle.has_usable_threat_policies() is True
    assert len(runner.calls) == len(EXCHANGE_ADAPTERS)
    assert all(call["shell"] is False for call in runner.calls)
    evidence = bundle_to_evidence(bundle)
    assert evidence["exchange_threat_usable"] is True
    assert evidence["proxy"] is False


def test_missing_module_maps_to_unavailable_typed_state() -> None:
    runner = ScriptedRunner(
        [
            BridgeProcessResult(
                0,
                _err("module_missing", "module_missing: ExchangeOnlineManagement"),
                b"",
                False,
                False,
                False,
            )
        ]
    )
    bundle = collect_exchange_bundle(
        ExchangeCollectOptions(
            adapters=(THREAT_ADAPTER,),
            runner=runner,
            executable=Path("/usr/bin/pwsh"),
        )
    )
    payload = bundle.adapters[THREAT_ADAPTER]
    surface = payload.surfaces["adapter"]
    assert surface.status is SurfaceStatus.UNAVAILABLE
    assert "module" in surface.reason.lower()
    assert bundle.has_usable_threat_policies() is False


def test_disconnected_session_maps_to_disconnected_or_unavailable() -> None:
    runner = ScriptedRunner(
        [
            BridgeProcessResult(
                0,
                _err("unavailable", "disconnected: Exchange Online session not connected"),
                b"",
                False,
                False,
                False,
            )
        ]
    )
    bundle = collect_exchange_bundle(
        ExchangeCollectOptions(
            adapters=(THREAT_ADAPTER,),
            runner=runner,
            executable=Path("/usr/bin/pwsh"),
        )
    )
    status = bundle.adapters[THREAT_ADAPTER].surfaces["adapter"].status
    assert status in {SurfaceStatus.DISCONNECTED, SurfaceStatus.UNAVAILABLE}


def test_denied_partial_surface_preserves_other_ok_surfaces() -> None:
    # Given: mixed surface statuses (partial access)
    partial: dict[str, JsonValue] = {
        "adapter": THREAT_ADAPTER,
        "module": "ExchangeOnlineManagement",
        "collection": "exchange_threat_policies",
        "surfaces": {
            "safe_links": {
                "surface": "safe_links",
                "status": "ok",
                "reason": "",
                "raw_count": 1,
                "items": [
                    {
                        "name": "Standard Preset Security Policy",
                        "kind": "preset_standard",
                        "enabled": True,
                        "properties": {},
                        "assignments": [],
                    }
                ],
            },
            "safe_attachments": {
                "surface": "safe_attachments",
                "status": "denied",
                "reason": "Access denied",
                "raw_count": 0,
                "items": [],
            },
            "preset_security": {
                "surface": "preset_security",
                "status": "ok",
                "reason": "",
                "raw_count": 1,
                "items": [
                    {
                        "name": "Standard Preset Security Policy",
                        "kind": "preset_standard",
                        "enabled": True,
                        "properties": {"State": "Enabled"},
                        "assignments": [],
                    }
                ],
            },
        },
    }
    payload = normalize_adapter_payload(partial, adapter=THREAT_ADAPTER)
    assert payload.surfaces["safe_links"].status is SurfaceStatus.OK
    assert payload.surfaces["safe_attachments"].status is SurfaceStatus.DENIED
    bundle = ExchangeBundle(adapters={THREAT_ADAPTER: payload})
    assert bundle.has_usable_threat_policies() is False


def test_security_payload_adapter_injection_never_spawns() -> None:
    runner = ScriptedRunner(
        [BridgeProcessResult(0, _ok(DEMO_THREAT_PAYLOAD), b"", False, False, False)]
    )
    from licenselens.collectors.powershell import BridgeInvokeRequest

    envelope = invoke_powershell_adapter(
        BridgeInvokeRequest(
            adapter="exo_threat_policies; rm -rf /",
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
                _ok(DEMO_THREAT_PAYLOAD),
                b"boom",
                False,
                False,
                False,
            )
        ]
    )
    bundle = collect_exchange_bundle(
        ExchangeCollectOptions(
            adapters=(THREAT_ADAPTER,),
            runner=runner,
            executable=Path("/usr/bin/pwsh"),
        )
    )
    assert bundle.has_usable_threat_policies() is False
    assert bundle.adapters[THREAT_ADAPTER].surfaces["adapter"].status is SurfaceStatus.ERROR


def test_mdo_evaluator_prefers_direct_exchange_over_proxy() -> None:
    # Given: usable direct threat policies
    evidence = demo_exchange_evidence()
    evidence["secure_score_controls"] = [
        {
            "controlName": "SafeLinks_Enabled",
            "score": 0.0,
            "maxScore": 1.0,
            "description": "should be ignored when direct present",
        }
    ]

    # When: MDO evaluator runs
    result = evaluate_mdo_p2_policies(_check(), evidence)

    # Then: direct path, not proxy
    assert result.evidence.get("proxy") is False
    assert result.evidence.get("exchange_direct") is True
    assert result.status in {FindingStatus.OK, FindingStatus.PARTIAL, FindingStatus.GAP}
    assert "powershell" in str(result.data_sources[0]).lower()


def test_mdo_evaluator_proxy_fallback_when_direct_unusable() -> None:
    from licenselens.collectors.secure_score import DEMO_SECURE_SCORE, extract_control_scores

    result = evaluate_mdo_p2_policies(
        _check(),
        {
            "exchange_threat_usable": False,
            "secure_score_controls": extract_control_scores(DEMO_SECURE_SCORE),
        },
    )
    assert result.evidence.get("proxy") is True
    assert result.status in {FindingStatus.PARTIAL, FindingStatus.GAP}


def test_unavailable_payload_helper() -> None:
    payload = unavailable_payload(
        "exo_dkim",
        reason="module_missing: ExchangeOnlineManagement",
        status=SurfaceStatus.UNAVAILABLE,
    )
    assert payload.surfaces["adapter"].status is SurfaceStatus.UNAVAILABLE


def test_adapter_scripts_contain_only_get_read_verbs_for_exo() -> None:
    # Given: all exchange adapters on disk
    # When: scanned for mutation cmdlets
    banned = (
        "Set-OrganizationConfig",
        "Set-RemoteDomain",
        "New-TransportRule",
        "Remove-TransportRule",
        "Set-MalwareFilterPolicy",
        "Set-SafeLinksPolicy",
        "Set-SafeAttachmentPolicy",
        "Set-AntiPhishPolicy",
        "New-DlpCompliancePolicy",
        "Remove-DlpCompliancePolicy",
        "Set-Label",
    )
    for name in EXCHANGE_ADAPTERS:
        text = (ROOT / "adapters" / f"{name}.ps1").read_text(encoding="utf-8")
        for cmd in banned:
            assert cmd not in text, f"{name} contains write cmdlet {cmd}"
