"""Collect Teams and SharePoint/OneDrive state via PowerShell bridge."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from licenselens.collectors.collaboration_demo import demo_collaboration_evidence
from licenselens.collectors.collaboration_fixtures import DEMO_FIXTURES
from licenselens.collectors.collaboration_models import (
    COLLABORATION_ADAPTERS,
    CollaborationAdapterPayload,
    CollaborationBundle,
)
from licenselens.collectors.collaboration_normalize import (
    CollaborationPayloadParseError,
    coverage_evidence_for_bundle,
    normalize_adapter_payload,
    surface_status_from_health,
    unavailable_payload,
)
from licenselens.collectors.contracts import (
    CloudEnvironment,
    EvidenceEnvelope,
    EvidenceHealth,
    EvidenceKey,
)
from licenselens.collectors.exchange_models import SurfaceStatus
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
    "DEMO_FIXTURES",
    "CollaborationCollectOptions",
    "bundle_to_evidence",
    "collect_collaboration_bundle",
    "collect_collaboration_evidence",
    "demo_collaboration_evidence",
]


@dataclass(frozen=True, slots=True)
class CollaborationCollectOptions:
    adapters: Sequence[str] = field(default_factory=lambda: COLLABORATION_ADAPTERS)
    cloud: CloudEnvironment = CloudEnvironment.PUBLIC
    auth: BridgeAuthMaterial = field(default_factory=BridgeAuthMaterial)
    limits: PowerShellBridgeLimits = field(default_factory=lambda: _DEFAULT_LIMITS)
    fixture_by_adapter: Mapping[str, JsonValue] = field(default_factory=dict)
    executable: Path | str | None | object | None = None
    module_root: Path | None = None
    runner: ProcessRunner | None = None


def collect_collaboration_bundle(
    options: CollaborationCollectOptions | None = None,
) -> CollaborationBundle:
    """Invoke allowlisted SPO/Teams adapters and normalize into CollaborationBundle."""
    opts = options if options is not None else CollaborationCollectOptions()
    adapters: dict[str, CollaborationAdapterPayload] = {}
    for name in opts.adapters:
        adapters[name] = _collect_one(name, opts)
    return CollaborationBundle(adapters=adapters, direct=True, proxy=False)


def collect_collaboration_evidence(
    options: CollaborationCollectOptions | None = None,
) -> dict[str, JsonValue]:
    """Runner-facing dict evidence (JSON-serializable)."""
    bundle = collect_collaboration_bundle(options)
    return bundle_to_evidence(bundle)


def bundle_to_evidence(bundle: CollaborationBundle) -> dict[str, JsonValue]:
    """Flatten bundle for evaluator evidence dicts."""
    coverage = [row.model_dump(mode="json") for row in coverage_evidence_for_bundle(bundle)]
    return {
        "collaboration_bundle": bundle.model_dump(mode="json"),
        "collaboration_direct": True,
        "collaboration_proxy": False,
        "collaboration_coverage": coverage,
        "source": "powershell.collaboration",
        "proxy": False,
    }


def _collect_one(adapter: str, opts: CollaborationCollectOptions) -> CollaborationAdapterPayload:
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


def _envelope_to_payload(
    adapter: str,
    envelope: EvidenceEnvelope,
) -> CollaborationAdapterPayload:
    match envelope.health:
        case EvidenceHealth.OK:
            try:
                return normalize_adapter_payload(envelope.value, adapter=adapter)
            except CollaborationPayloadParseError as exc:
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
