"""Versioned, allowlisted PowerShell bridge process contract.

Security boundary:
- argv arrays only; never shell=True
- adapter names allowlisted against checked-in files under the module tree
- UTF-8 JSON on bounded stdin/stdout
- secrets redacted from captured stderr/stdout used in diagnostics
- missing executable/module, unsupported cloud, timeout, malformed/oversized
  output, and nonzero exit become typed EvidenceEnvelope states
"""

from __future__ import annotations

import json
import re
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from re import Pattern
from typing import Final, Protocol

from licenselens.collectors.contracts import (
    CloudEnvironment,
    EvidenceEnvelope,
    EvidenceKey,
)
from licenselens.collectors.powershell_process import (
    BoundedProcessRunner,
    BridgeProcessResult,
)
from licenselens.collectors.powershell_result import (
    BRIDGE_PROTOCOL_VERSION,
    map_process_result,
    redact_secrets,
)
from licenselens.schema_contracts import JsonValue

BRIDGE_ENTRY_SCRIPT: Final = "Invoke-LicenseLensBridge.ps1"
ADAPTER_NAME_PATTERN: Final[Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
SUPPORTED_BRIDGE_CLOUDS: Final[frozenset[CloudEnvironment]] = frozenset({CloudEnvironment.PUBLIC})
_AUTO_EXECUTABLE: Final = object()

__all__ = [
    "BRIDGE_PROTOCOL_VERSION",
    "BridgeAuthMaterial",
    "BridgeInvokeRequest",
    "BridgeProcessResult",
    "PowerShellBridgeLimits",
    "find_powershell_executable",
    "invoke_powershell_adapter",
    "list_allowlisted_adapters",
    "powershell_module_root",
    "redact_secrets",
    "resolve_adapter_path",
]


@dataclass(frozen=True, slots=True)
class PowerShellBridgeLimits:
    timeout_seconds: float = 60.0
    max_stdout_bytes: int = 8 * 1024 * 1024
    max_stderr_bytes: int = 256 * 1024
    max_stdin_bytes: int = 256 * 1024


@dataclass(frozen=True, slots=True)
class BridgeAuthMaterial:
    mode: str = "none"
    access_token: str | None = None
    tenant_id: str | None = None
    client_id: str | None = None


@dataclass(frozen=True, slots=True)
class BridgeInvokeRequest:
    adapter: str
    cloud: CloudEnvironment = CloudEnvironment.PUBLIC
    auth: BridgeAuthMaterial = field(default_factory=BridgeAuthMaterial)
    params: Mapping[str, JsonValue] = field(default_factory=dict)
    evidence_key: EvidenceKey = EvidenceKey("powershell")


class ProcessRunner(Protocol):
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
    ) -> BridgeProcessResult: ...


def powershell_module_root() -> Path:
    """Resolve the checked-in LicenseLens.Collectors module directory."""
    here = Path(__file__).resolve()
    candidate = here.parents[3] / "powershell" / "LicenseLens.Collectors"
    if candidate.is_dir():
        return candidate
    return here.parents[1] / "data" / "powershell" / "LicenseLens.Collectors"


def list_allowlisted_adapters(module_root: Path | None = None) -> frozenset[str]:
    root = module_root if module_root is not None else powershell_module_root()
    adapters_dir = root / "adapters"
    if not adapters_dir.is_dir():
        return frozenset()
    names: set[str] = set()
    for path in adapters_dir.glob("*.ps1"):
        name = path.stem
        if ADAPTER_NAME_PATTERN.fullmatch(name) is None:
            continue
        if not _is_safe_child(path.resolve(), adapters_dir.resolve()):
            continue
        names.add(name)
    return frozenset(names)


def resolve_adapter_path(adapter: str, *, module_root: Path | None = None) -> Path:
    """Return the checked-in adapter path or raise ValueError if not allowlisted."""
    if ADAPTER_NAME_PATTERN.fullmatch(adapter) is None:
        msg = f"adapter not allowlisted: {adapter!r}"
        raise ValueError(msg)
    root = module_root if module_root is not None else powershell_module_root()
    adapters_dir = (root / "adapters").resolve()
    candidate = (adapters_dir / f"{adapter}.ps1").resolve()
    if not _is_safe_child(candidate, adapters_dir) or not candidate.is_file():
        msg = f"adapter not allowlisted: {adapter!r}"
        raise ValueError(msg)
    if adapter not in list_allowlisted_adapters(root):
        msg = f"adapter not allowlisted: {adapter!r}"
        raise ValueError(msg)
    return candidate


def find_powershell_executable() -> Path | None:
    for name in ("pwsh", "powershell"):
        found = shutil.which(name)
        if found is not None:
            return Path(found)
    return None


def invoke_powershell_adapter(
    request: BridgeInvokeRequest,
    *,
    limits: PowerShellBridgeLimits | None = None,
    executable: Path | str | None | object = _AUTO_EXECUTABLE,
    module_root: Path | None = None,
    runner: ProcessRunner | None = None,
) -> EvidenceEnvelope:
    """Invoke one allowlisted adapter and map the outcome to EvidenceEnvelope."""
    bounds = limits if limits is not None else PowerShellBridgeLimits()
    key = request.evidence_key
    root = module_root if module_root is not None else powershell_module_root()

    if request.cloud not in SUPPORTED_BRIDGE_CLOUDS:
        return EvidenceEnvelope.unsupported(
            key,
            reason=f"unsupported cloud for powershell bridge: {request.cloud.value}",
        )

    if not root.is_dir() or not (root / BRIDGE_ENTRY_SCRIPT).is_file():
        return EvidenceEnvelope.unavailable(
            key,
            reason="powershell module not found",
        )

    try:
        resolve_adapter_path(request.adapter, module_root=root)
    except ValueError as exc:
        return EvidenceEnvelope.error(key, reason=str(exc))

    exe = _resolve_executable(executable)
    if exe is None:
        return EvidenceEnvelope.unavailable(
            key,
            reason="powershell executable not found",
        )

    stdin = _encode_request(request, bounds=bounds)
    if stdin is None:
        return EvidenceEnvelope.error(key, reason="powershell bridge request exceeded stdin cap")

    process_runner = runner if runner is not None else BoundedProcessRunner()
    result = process_runner.run(
        _build_argv(exe, root),
        stdin=stdin,
        timeout_seconds=bounds.timeout_seconds,
        max_stdout_bytes=bounds.max_stdout_bytes,
        max_stderr_bytes=bounds.max_stderr_bytes,
        cwd=root,
        env={"POWERSHELL_TELEMETRY_OPTOUT": "1"},
    )
    return map_process_result(
        evidence_key=key,
        result=result,
        extra_secrets=_secret_values(request.auth),
    )


def _resolve_executable(executable: Path | str | None | object) -> Path | None:
    if executable is _AUTO_EXECUTABLE:
        return find_powershell_executable()
    if executable is None:
        return None
    if isinstance(executable, Path):
        return executable
    if isinstance(executable, str):
        return Path(executable)
    msg = f"unsupported executable type: {type(executable)!r}"
    raise TypeError(msg)


def _build_argv(executable: Path, module_root: Path) -> list[str]:
    return [
        str(executable),
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(module_root / BRIDGE_ENTRY_SCRIPT),
    ]


def _encode_request(
    request: BridgeInvokeRequest,
    *,
    bounds: PowerShellBridgeLimits,
) -> bytes | None:
    payload: dict[str, JsonValue] = {
        "protocol_version": BRIDGE_PROTOCOL_VERSION,
        "adapter": request.adapter,
        "cloud": request.cloud.value,
        "auth": {
            "mode": request.auth.mode,
            "access_token": request.auth.access_token,
            "tenant_id": request.auth.tenant_id,
            "client_id": request.auth.client_id,
        },
        "params": dict(request.params),
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(raw) > bounds.max_stdin_bytes:
        return None
    return raw


def _secret_values(auth: BridgeAuthMaterial) -> tuple[str, ...]:
    if auth.access_token:
        return (auth.access_token,)
    return ()


def _is_safe_child(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True
