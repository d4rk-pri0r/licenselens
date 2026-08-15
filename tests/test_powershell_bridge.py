"""Contract tests for the constrained PowerShell bridge process."""

from __future__ import annotations

import json
import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

import pytest

from licenselens.collectors.contracts import CloudEnvironment, EvidenceHealth, EvidenceKey
from licenselens.collectors.powershell import (
    BRIDGE_PROTOCOL_VERSION,
    BridgeAuthMaterial,
    BridgeInvokeRequest,
    BridgeProcessResult,
    PowerShellBridgeLimits,
    find_powershell_executable,
    invoke_powershell_adapter,
    list_allowlisted_adapters,
    powershell_module_root,
    redact_secrets,
    resolve_adapter_path,
)
from licenselens.schema_contracts import JsonValue

FAKE_ADAPTER: Final = "fake_echo"
SECRET_TOKEN: Final = "super-secret-token-value-xyz"
JWT_LIKE: Final = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepart"


class ScriptedRunner:
    """Deterministic process double for bridge contract tests."""

    def __init__(
        self,
        *,
        result: BridgeProcessResult | None = None,
        results: Sequence[BridgeProcessResult] | None = None,
        raise_on_call: Exception | None = None,
    ) -> None:
        self._results = list(results) if results is not None else []
        if result is not None:
            self._results.insert(0, result)
        self._raise_on_call = raise_on_call
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
                "timeout_seconds": timeout_seconds,
                "max_stdout_bytes": max_stdout_bytes,
                "max_stderr_bytes": max_stderr_bytes,
                "cwd": cwd,
                "env": dict(env) if env is not None else None,
                "shell": False,
            }
        )
        if self._raise_on_call is not None:
            raise self._raise_on_call
        if not self._results:
            msg = "ScriptedRunner has no remaining results"
            raise AssertionError(msg)
        return self._results.pop(0)


def _ok_payload(*, data: Mapping[str, JsonValue] | None = None) -> bytes:
    body: dict[str, JsonValue] = {
        "protocol_version": BRIDGE_PROTOCOL_VERSION,
        "ok": True,
        "adapter": FAKE_ADAPTER,
        "module_version": "0.1.0",
        "cloud": "public",
        "data": dict(data or {"echo": "ok"}),
        "error": None,
    }
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _err_payload(
    *,
    code: str,
    message: str,
    ok: bool = False,
) -> bytes:
    body: dict[str, JsonValue] = {
        "protocol_version": BRIDGE_PROTOCOL_VERSION,
        "ok": ok,
        "adapter": FAKE_ADAPTER,
        "module_version": "0.1.0",
        "cloud": "public",
        "data": None,
        "error": {"code": code, "message": message},
    }
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _request(**overrides: object) -> BridgeInvokeRequest:
    base = BridgeInvokeRequest(
        adapter=FAKE_ADAPTER,
        cloud=CloudEnvironment.PUBLIC,
        auth=BridgeAuthMaterial(mode="none"),
        params={"probe": "value"},
        evidence_key=EvidenceKey("ps.fake_echo"),
    )
    if not overrides:
        return base
    fields = {
        "adapter": base.adapter,
        "cloud": base.cloud,
        "auth": base.auth,
        "params": base.params,
        "evidence_key": base.evidence_key,
    }
    fields.update(overrides)
    return BridgeInvokeRequest(**fields)  # type: ignore[arg-type]


def test_list_allowlisted_adapters_includes_checked_in_fake_and_exchange() -> None:
    # Given: the checked-in PowerShell module tree
    root = powershell_module_root()

    # When: adapters are enumerated from disk
    adapters = list_allowlisted_adapters(root)

    # Then: fake_echo plus Exchange/SCC adapters (Wave 2 todo 13)
    assert FAKE_ADAPTER in adapters
    assert "exo_threat_policies" in adapters
    assert "scc_compliance" in adapters
    assert ".." not in adapters
    assert all(name.isidentifier() or "_" in name for name in adapters)


def test_resolve_adapter_path_rejects_traversal_and_unknown_names() -> None:
    root = powershell_module_root()

    with pytest.raises(ValueError, match="not allowlisted"):
        resolve_adapter_path("../etc/passwd", module_root=root)
    with pytest.raises(ValueError, match="not allowlisted"):
        resolve_adapter_path("fake_echo; rm -rf /", module_root=root)
    with pytest.raises(ValueError, match="not allowlisted"):
        resolve_adapter_path("not_a_real_adapter", module_root=root)

    path = resolve_adapter_path(FAKE_ADAPTER, module_root=root)
    assert path.is_file()
    assert path.parent == root / "adapters"
    assert path.resolve().is_relative_to(root.resolve())


def test_happy_path_fake_adapter_parses_json_envelope() -> None:
    # Given: a scripted successful fake adapter response
    runner = ScriptedRunner(
        result=BridgeProcessResult(
            exit_code=0,
            stdout=_ok_payload(data={"echo": "hello", "n": 1}),
            stderr=b"",
            timed_out=False,
            stdout_truncated=False,
            stderr_truncated=False,
        )
    )

    # When: the bridge is invoked
    envelope = invoke_powershell_adapter(
        _request(),
        runner=runner,
        executable=Path("/usr/bin/pwsh"),
    )

    # Then: usable OK evidence with parsed data
    assert envelope.health is EvidenceHealth.OK
    assert envelope.is_usable
    assert envelope.value == {"echo": "hello", "n": 1}
    assert len(runner.calls) == 1
    call = runner.calls[0]
    argv = call["argv"]
    assert isinstance(argv, list)
    assert argv[0] == "/usr/bin/pwsh"
    assert "-File" in argv
    assert all(isinstance(part, str) for part in argv)
    assert call["shell"] is False
    stdin = call["stdin"]
    assert isinstance(stdin, bytes)
    request_body = json.loads(stdin.decode("utf-8"))
    assert request_body["protocol_version"] == BRIDGE_PROTOCOL_VERSION
    assert request_body["adapter"] == FAKE_ADAPTER
    assert request_body["cloud"] == "public"


def test_command_injection_adapter_name_never_reaches_process() -> None:
    # Given: attacker-controlled adapter name with shell metacharacters
    runner = ScriptedRunner(
        result=BridgeProcessResult(
            exit_code=0,
            stdout=_ok_payload(),
            stderr=b"",
            timed_out=False,
            stdout_truncated=False,
            stderr_truncated=False,
        )
    )
    malicious = "fake_echo; Get-Process | Out-Null #$(id)"

    # When: invoke is attempted
    envelope = invoke_powershell_adapter(
        _request(adapter=malicious),
        runner=runner,
        executable=Path("/usr/bin/pwsh"),
    )

    # Then: fail closed before process spawn; no argv recorded
    assert envelope.health is EvidenceHealth.ERROR
    assert "not allowlisted" in envelope.reason
    assert runner.calls == []


def test_missing_executable_is_unavailable() -> None:
    envelope = invoke_powershell_adapter(
        _request(),
        executable=None,
        runner=ScriptedRunner(result=BridgeProcessResult(0, b"", b"", False, False, False)),
    )
    assert envelope.health is EvidenceHealth.UNAVAILABLE
    assert "executable" in envelope.reason.lower()


def test_unsupported_cloud_is_unsupported_without_process() -> None:
    runner = ScriptedRunner(result=BridgeProcessResult(0, _ok_payload(), b"", False, False, False))
    envelope = invoke_powershell_adapter(
        _request(cloud=CloudEnvironment.CHINA),
        runner=runner,
        executable=Path("/usr/bin/pwsh"),
    )
    assert envelope.health is EvidenceHealth.UNSUPPORTED
    assert "cloud" in envelope.reason.lower()
    assert runner.calls == []


def test_timeout_maps_to_error_state() -> None:
    runner = ScriptedRunner(
        result=BridgeProcessResult(
            exit_code=-1,
            stdout=b"",
            stderr=b"still running",
            timed_out=True,
            stdout_truncated=False,
            stderr_truncated=False,
        )
    )
    envelope = invoke_powershell_adapter(
        _request(),
        runner=runner,
        executable=Path("/usr/bin/pwsh"),
        limits=PowerShellBridgeLimits(timeout_seconds=0.05),
    )
    assert envelope.health is EvidenceHealth.ERROR
    assert "timed out" in envelope.reason.lower()


def test_malformed_json_maps_to_error_state() -> None:
    runner = ScriptedRunner(
        result=BridgeProcessResult(
            exit_code=0,
            stdout=b"not-json{{{{",
            stderr=b"",
            timed_out=False,
            stdout_truncated=False,
            stderr_truncated=False,
        )
    )
    envelope = invoke_powershell_adapter(
        _request(),
        runner=runner,
        executable=Path("/usr/bin/pwsh"),
    )
    assert envelope.health is EvidenceHealth.ERROR
    assert "malformed" in envelope.reason.lower()


def test_oversized_stdout_maps_to_error_state() -> None:
    runner = ScriptedRunner(
        result=BridgeProcessResult(
            exit_code=0,
            stdout=_ok_payload(),
            stderr=b"",
            timed_out=False,
            stdout_truncated=True,
            stderr_truncated=False,
        )
    )
    envelope = invoke_powershell_adapter(
        _request(),
        runner=runner,
        executable=Path("/usr/bin/pwsh"),
    )
    assert envelope.health is EvidenceHealth.ERROR
    assert "cap" in envelope.reason.lower() or "exceed" in envelope.reason.lower()


def test_nonzero_exit_maps_to_error_even_with_misleading_ok_json() -> None:
    # Given: process exits non-zero but stdout claims success (misleading success)
    runner = ScriptedRunner(
        result=BridgeProcessResult(
            exit_code=7,
            stdout=_ok_payload(data={"trusted": True}),
            stderr=b"boom",
            timed_out=False,
            stdout_truncated=False,
            stderr_truncated=False,
        )
    )
    envelope = invoke_powershell_adapter(
        _request(),
        runner=runner,
        executable=Path("/usr/bin/pwsh"),
    )
    assert envelope.health is EvidenceHealth.ERROR
    assert envelope.value is None or envelope.is_usable is False
    assert "exit" in envelope.reason.lower() or "nonzero" in envelope.reason.lower()


def test_bridge_error_codes_map_to_typed_health() -> None:
    cases = [
        ("denied", EvidenceHealth.DENIED),
        ("unsupported_cloud", EvidenceHealth.UNSUPPORTED),
        ("module_missing", EvidenceHealth.UNAVAILABLE),
        ("adapter_failed", EvidenceHealth.ERROR),
    ]
    for code, expected in cases:
        runner = ScriptedRunner(
            result=BridgeProcessResult(
                exit_code=0,
                stdout=_err_payload(code=code, message=f"detail-{code}"),
                stderr=b"",
                timed_out=False,
                stdout_truncated=False,
                stderr_truncated=False,
            )
        )
        envelope = invoke_powershell_adapter(
            _request(),
            runner=runner,
            executable=Path("/usr/bin/pwsh"),
        )
        assert envelope.health is expected, code
        assert code.replace("_", " ") in envelope.reason.lower() or code in envelope.reason.lower()


def test_secret_material_is_redacted_from_reasons_and_never_in_argv() -> None:
    # Given: auth carries a secret and stderr echoes it
    auth = BridgeAuthMaterial(
        mode="token",
        access_token=SECRET_TOKEN,
        tenant_id="tenant-1",
        client_id="client-1",
    )
    stderr = f"Authorization: Bearer {SECRET_TOKEN}\naccess_token={SECRET_TOKEN}\n".encode()
    runner = ScriptedRunner(
        result=BridgeProcessResult(
            exit_code=1,
            stdout=b"",
            stderr=stderr,
            timed_out=False,
            stdout_truncated=False,
            stderr_truncated=False,
        )
    )

    envelope = invoke_powershell_adapter(
        _request(auth=auth),
        runner=runner,
        executable=Path("/usr/bin/pwsh"),
    )

    assert envelope.health is EvidenceHealth.ERROR
    assert SECRET_TOKEN not in envelope.reason
    assert "Bearer ***" in envelope.reason or "***" in envelope.reason
    call = runner.calls[0]
    argv = call["argv"]
    assert isinstance(argv, list)
    assert SECRET_TOKEN not in argv
    stdin = call["stdin"]
    assert isinstance(stdin, bytes)
    # Secret may travel on stdin JSON only (not argv/logs); reason must stay redacted.
    assert SECRET_TOKEN.encode() in stdin


def test_redact_secrets_covers_jwt_and_labeled_fields() -> None:
    raw = f"token={JWT_LIKE} password=hunter2 client_secret=abc123"
    cleaned = redact_secrets(raw)
    assert JWT_LIKE not in cleaned
    assert "hunter2" not in cleaned
    assert "abc123" not in cleaned
    assert "***" in cleaned


def test_argv_never_uses_shell_and_uses_argument_array_only() -> None:
    runner = ScriptedRunner(result=BridgeProcessResult(0, _ok_payload(), b"", False, False, False))
    invoke_powershell_adapter(
        _request(),
        runner=runner,
        executable=Path("/bin/pwsh"),
    )
    call = runner.calls[0]
    argv = call["argv"]
    assert isinstance(argv, list)
    # No shell metacharacter concatenation — discrete argv tokens only.
    joined = " ".join(argv)
    assert "&&" not in joined
    assert "|" not in joined
    assert "$( " not in joined
    assert call["shell"] is False
    assert "-NoProfile" in argv
    assert "-NonInteractive" in argv
    assert "-File" in argv


def test_missing_module_root_is_unavailable() -> None:
    missing = Path("/tmp/licenselens-missing-ps-module-does-not-exist")
    envelope = invoke_powershell_adapter(
        _request(),
        runner=ScriptedRunner(result=BridgeProcessResult(0, b"", b"", False, False, False)),
        executable=Path("/usr/bin/pwsh"),
        module_root=missing,
    )
    assert envelope.health is EvidenceHealth.UNAVAILABLE
    assert "module" in envelope.reason.lower()


def test_bounded_process_runner_times_out_hung_command() -> None:
    # Given: a real hung child process (not PowerShell-specific)
    from licenselens.collectors.powershell_process import BoundedProcessRunner

    runner = BoundedProcessRunner()
    # When: timeout is shorter than sleep
    result = runner.run(
        [str(Path(__import__("sys").executable)), "-c", "import time; time.sleep(30)"],
        stdin=b"",
        timeout_seconds=0.2,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
        cwd=None,
        env=None,
    )
    # Then: timeout is observed and process is cleaned up
    assert result.timed_out is True
    assert result.exit_code != 0 or result.timed_out


def test_bounded_process_runner_caps_stdout() -> None:
    from licenselens.collectors.powershell_process import BoundedProcessRunner

    runner = BoundedProcessRunner()
    result = runner.run(
        [
            str(Path(__import__("sys").executable)),
            "-c",
            "import sys; sys.stdout.buffer.write(b'x' * 100_000)",
        ],
        stdin=b"",
        timeout_seconds=5.0,
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
        cwd=None,
        env=None,
    )
    assert result.stdout_truncated is True
    assert len(result.stdout) <= 1024


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not installed")
def test_live_pwsh_fake_adapter_round_trip() -> None:
    # Given: real pwsh and checked-in fake adapter
    executable = find_powershell_executable()
    assert executable is not None

    # When: bridge runs the live process contract
    envelope = invoke_powershell_adapter(
        _request(params={"live": True, "marker": "contract-12"}),
        executable=executable,
        limits=PowerShellBridgeLimits(timeout_seconds=30.0),
    )

    # Then: happy-path envelope from real PowerShell
    assert envelope.health is EvidenceHealth.OK
    assert isinstance(envelope.value, dict)
    assert envelope.value.get("adapter") == FAKE_ADAPTER
    assert envelope.value.get("marker") == "contract-12"
