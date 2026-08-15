"""Bounded subprocess runner for the PowerShell bridge (shell=False only)."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

_READ_CHUNK: Final = 65_536
_KILL_GRACE_SECONDS: Final = 0.5


@dataclass(frozen=True, slots=True)
class BridgeProcessResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool


class BoundedProcessRunner:
    """Run argv with shell=False, timeout, and stdout/stderr byte caps."""

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
        if not argv:
            msg = "argv must not be empty"
            raise ValueError(msg)

        merged_env = os.environ.copy()
        if env is not None:
            merged_env.update(env)

        proc = subprocess.Popen(  # noqa: S603 — argv-only, shell=False by design
            list(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd) if cwd is not None else None,
            env=merged_env,
            shell=False,
            start_new_session=True,
        )
        return _drain_process(
            proc,
            stdin=stdin,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )


def _drain_process(
    proc: subprocess.Popen[bytes],
    *,
    stdin: bytes,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> BridgeProcessResult:
    stdout_buf = bytearray()
    stderr_buf = bytearray()
    stdout_truncated = False
    stderr_truncated = False
    timed_out = False
    lock = threading.Lock()

    def _read_stream(
        stream: object,
        buf: bytearray,
        limit: int,
        flag_name: str,
    ) -> None:
        nonlocal stdout_truncated, stderr_truncated
        read = getattr(stream, "read", None)
        if read is None:
            return
        while True:
            chunk = read(_READ_CHUNK)
            if not chunk:
                break
            with lock:
                room = limit - len(buf)
                if room <= 0:
                    if flag_name == "stdout":
                        stdout_truncated = True
                    else:
                        stderr_truncated = True
                    break
                if len(chunk) > room:
                    buf.extend(chunk[:room])
                    if flag_name == "stdout":
                        stdout_truncated = True
                    else:
                        stderr_truncated = True
                    break
                buf.extend(chunk)

    assert proc.stdout is not None
    assert proc.stderr is not None
    assert proc.stdin is not None

    out_thread = threading.Thread(
        target=_read_stream,
        args=(proc.stdout, stdout_buf, max_stdout_bytes, "stdout"),
        daemon=True,
    )
    err_thread = threading.Thread(
        target=_read_stream,
        args=(proc.stderr, stderr_buf, max_stderr_bytes, "stderr"),
        daemon=True,
    )
    out_thread.start()
    err_thread.start()

    try:
        proc.stdin.write(stdin)
        proc.stdin.close()
    except BrokenPipeError:
        pass

    deadline = time.monotonic() + max(timeout_seconds, 0.0)
    while proc.poll() is None:
        if time.monotonic() >= deadline:
            timed_out = True
            _terminate_tree(proc)
            break
        if stdout_truncated or stderr_truncated:
            _terminate_tree(proc)
            break
        time.sleep(0.01)

    out_thread.join(timeout=1.0)
    err_thread.join(timeout=1.0)
    exit_code = proc.poll()
    if exit_code is None:
        _terminate_tree(proc)
        exit_code = proc.wait(timeout=2.0)

    return BridgeProcessResult(
        exit_code=int(exit_code),
        stdout=bytes(stdout_buf),
        stderr=bytes(stderr_buf),
        timed_out=timed_out,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
    )


def _terminate_tree(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    try:
        if hasattr(os, "killpg"):
            os.killpg(proc.pid, signal.SIGTERM)
        else:  # pragma: no cover - Windows
            proc.terminate()
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        proc.wait(timeout=_KILL_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            if hasattr(os, "killpg"):
                os.killpg(proc.pid, signal.SIGKILL)
            else:  # pragma: no cover - Windows
                proc.kill()
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            proc.wait(timeout=_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
