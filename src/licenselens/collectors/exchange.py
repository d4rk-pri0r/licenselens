"""Collect Exchange Online and Security/Compliance state via PowerShell bridge."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from licenselens.collectors.contracts import (
    CloudEnvironment,
    EvidenceEnvelope,
    EvidenceHealth,
    EvidenceKey,
)
from licenselens.collectors.exchange_demo import DEMO_THREAT_PAYLOAD, demo_exchange_evidence
from licenselens.collectors.exchange_models import (
    EXCHANGE_ADAPTERS,
    THREAT_ADAPTER,
    ExchangeAdapterPayload,
    ExchangeBundle,
    SurfaceStatus,
)
from licenselens.collectors.exchange_normalize import (
    ExchangePayloadParseError,
    normalize_adapter_payload,
    surface_status_from_health,
    unavailable_payload,
)
from licenselens.collectors.powershell import (
    BridgeAuthMaterial,
    BridgeInvokeRequest,
    PowerShellBridgeLimits,
    ProcessRunner,
    invoke_powershell_adapter,
)
from licenselens.schema_contracts import JsonValue

_DEFAULT_LIMITS: Final = PowerShellBridgeLimits(timeout_seconds=120.0)

__all__ = [
    "DEMO_THREAT_PAYLOAD",
    "ExchangeCollectOptions",
    "bundle_to_evidence",
    "collect_exchange_bundle",
    "collect_exchange_evidence",
    "demo_exchange_evidence",
]


@dataclass(frozen=True, slots=True)
class ExchangeCollectOptions:
    adapters: Sequence[str] = field(default_factory=lambda: EXCHANGE_ADAPTERS)
    cloud: CloudEnvironment = CloudEnvironment.PUBLIC
    auth: BridgeAuthMaterial = field(default_factory=BridgeAuthMaterial)
    limits: PowerShellBridgeLimits = field(default_factory=lambda: _DEFAULT_LIMITS)
    fixture_by_adapter: Mapping[str, JsonValue] = field(default_factory=dict)
    executable: Path | str | None | object | None = None
    module_root: Path | None = None
    runner: ProcessRunner | None = None


def collect_exchange_bundle(options: ExchangeCollectOptions | None = None) -> ExchangeBundle:
    """Invoke allowlisted EXO/SCC adapters and normalize into ExchangeBundle."""
    opts = options if options is not None else ExchangeCollectOptions()
    adapters: dict[str, ExchangeAdapterPayload] = {}
    for name in opts.adapters:
        adapters[name] = _collect_one(name, opts)
    return ExchangeBundle(adapters=adapters, direct=True, proxy=False)


def collect_exchange_evidence(
    options: ExchangeCollectOptions | None = None,
) -> dict[str, JsonValue]:
    """Runner-facing dict evidence (JSON-serializable)."""
    bundle = collect_exchange_bundle(options)
    return bundle_to_evidence(bundle)


def bundle_to_evidence(bundle: ExchangeBundle) -> dict[str, JsonValue]:
    """Flatten bundle for evaluator evidence dicts."""
    threat = bundle.adapters.get(THREAT_ADAPTER)
    return {
        "exchange_bundle": bundle.model_dump(mode="json"),
        "exchange_direct": True,
        "exchange_proxy": False,
        "exchange_threat_usable": bundle.has_usable_threat_policies(),
        "exchange_threat_policies": (
            threat.model_dump(mode="json") if threat is not None else None
        ),
        "source": "powershell.exchange",
        "proxy": False,
    }


def _collect_one(adapter: str, opts: ExchangeCollectOptions) -> ExchangeAdapterPayload:
    fixture = opts.fixture_by_adapter.get(adapter)
    params: dict[str, JsonValue] = {}
    if fixture is not None:
        params = {"fixture_mode": True, "fixture_data": fixture}

    request = BridgeInvokeRequest(
        adapter=adapter,
        cloud=opts.cloud,
        auth=opts.auth,
        params=params,
        evidence_key=EvidenceKey(f"ps.{adapter}"),
    )
    if opts.executable is not None:
        envelope = invoke_powershell_adapter(
            request,
            limits=opts.limits,
            executable=opts.executable,
            module_root=opts.module_root,
            runner=opts.runner,
        )
    else:
        envelope = invoke_powershell_adapter(
            request,
            limits=opts.limits,
            module_root=opts.module_root,
            runner=opts.runner,
        )
    return _envelope_to_payload(adapter, envelope)


def _envelope_to_payload(adapter: str, envelope: EvidenceEnvelope) -> ExchangeAdapterPayload:
    match envelope.health:
        case EvidenceHealth.OK:
            try:
                return normalize_adapter_payload(envelope.value, adapter=adapter)
            except ExchangePayloadParseError as exc:
                return unavailable_payload(
                    adapter,
                    reason=str(exc),
                    status=SurfaceStatus.ERROR,
                )
        case EvidenceHealth.DENIED:
            return unavailable_payload(
                adapter,
                reason=envelope.reason or "denied",
                status=SurfaceStatus.DENIED,
            )
        case EvidenceHealth.UNAVAILABLE:
            status = surface_status_from_health("unavailable")
            if "disconnect" in envelope.reason.lower():
                status = SurfaceStatus.DISCONNECTED
            if "module" in envelope.reason.lower():
                status = SurfaceStatus.UNAVAILABLE
            return unavailable_payload(adapter, reason=envelope.reason, status=status)
        case EvidenceHealth.UNSUPPORTED:
            return unavailable_payload(
                adapter,
                reason=envelope.reason or "unsupported",
                status=SurfaceStatus.UNSUPPORTED,
            )
        case EvidenceHealth.ERROR | EvidenceHealth.TRUNCATED | EvidenceHealth.MISSING:
            return unavailable_payload(
                adapter,
                reason=envelope.reason or envelope.health.value,
                status=SurfaceStatus.ERROR,
            )
        case unreachable:
            from typing import assert_never

            assert_never(unreachable)
