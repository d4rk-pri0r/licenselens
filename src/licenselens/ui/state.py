"""Scan session state for the local ui wizard.

Thread-safe state shared between the wizard's worker threads and (later)
its request handlers. Orchestration only: this module reuses the public
engine, auth, and report APIs — it never reimplements collectors,
evaluators, report rendering, or diffing.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from licenselens.auth import (
    AuthContext,
    AuthMode,
    DeviceCodePromptCallback,
    build_auth_context,
)
from licenselens.cli_scan_config import ScanConfigError
from licenselens.collectors.contracts import CollectorId, EvidenceEnvelope
from licenselens.config_models import RedactionSettings
from licenselens.diff_report import write_diff_report
from licenselens.engine.profiles import (
    ProfileReferenceError,
    ResolvedProfile,
    compose_profile,
)
from licenselens.engine.runner import run_scan
from licenselens.report import write_html_report, write_json_report

__all__ = [
    "DEFAULT_PROFILE_ID",
    "ProgressEvent",
    "ScanSession",
    "UiState",
]

#: Profile selected when the wizard user picks nothing.
DEFAULT_PROFILE_ID: Final = "core"

#: Canonical report artifact stem shared with the CLI layout.
_REPORT_STEM: Final = "security-license-lens-report"

#: Diff artifact written next to the "before" scan JSON by default.
_DIFF_FILENAME: Final = "diff-report.md"


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    """One collection step, as recorded from the engine progress hook."""

    collector_id: str
    index: int
    total: int
    status: str
    items: int


class UiState:
    """Thread-safe state for one wizard session.

    All slots are guarded by a single lock; readers get snapshots so
    callers never iterate a list another thread is appending to.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._status: str = "idle"
        self._progress: list[ProgressEvent] = []
        self._report_paths: dict[str, str] = {}
        self._device_code: tuple[str, str, datetime] | None = None

    # -- progress -----------------------------------------------------

    def record_progress(
        self,
        collector_id: CollectorId,
        index: int,
        total: int,
        envelope: EvidenceEnvelope,
    ) -> None:
        """Store one engine progress event; safe from worker threads."""
        event = ProgressEvent(
            collector_id=str(collector_id),
            index=index,
            total=total,
            status=envelope.collection_status.value,
            items=envelope.metadata.items_collected,
        )
        with self._lock:
            self._progress.append(event)

    def snapshot_progress(self) -> list[ProgressEvent]:
        """Copy of the progress events recorded so far, in order."""
        with self._lock:
            return list(self._progress)

    # -- status -------------------------------------------------------

    def set_status(self, status: str) -> None:
        with self._lock:
            self._status = status

    @property
    def status(self) -> str:
        with self._lock:
            return self._status

    # -- report artifacts ----------------------------------------------

    def record_report(self, name: str, path: Path) -> None:
        with self._lock:
            self._report_paths[name] = str(path)

    def snapshot_report_paths(self) -> dict[str, str]:
        with self._lock:
            return dict(self._report_paths)

    # -- device-code capture --------------------------------------------

    @property
    def device_code_prompt(self) -> DeviceCodePromptCallback:
        """Callback for ``build_auth_context`` capturing the device code silently.

        Stores ``(verification_url, user_code, expires_on)`` for the
        sign-in screen. Never prints or logs the code.
        """

        def _capture(verification_url: str, user_code: str, expires_on: datetime) -> None:
            with self._lock:
                self._device_code = (verification_url, user_code, expires_on)

        return _capture

    def snapshot_device_code(self) -> tuple[str, str, datetime] | None:
        with self._lock:
            return self._device_code


def _fresh_scan_dir(output_dir: Path) -> Path:
    """Return a fresh per-run subdirectory so a prior scan is preserved."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    candidate = output_dir / f"scan-{stamp}"
    counter = 1
    while candidate.exists():
        counter += 1
        candidate = output_dir / f"scan-{stamp}-{counter}"
    return candidate


def _resolve_profile(profile_id: str | None) -> ResolvedProfile:
    """Resolve a builtin profile, defaulting to ``core``; house error if unknown."""
    try:
        return compose_profile(profile_id or DEFAULT_PROFILE_ID)
    except ProfileReferenceError as exc:
        raise ScanConfigError(str(exc)) from exc


class ScanSession:
    """One wizard-driven scan: public engine APIs in, report artifacts out."""

    def __init__(
        self,
        state: UiState | None = None,
        *,
        redaction: RedactionSettings | None = None,
    ) -> None:
        self.state = state if state is not None else UiState()
        self._redaction = redaction

    def start_demo(
        self,
        output_dir: Path,
        profile_id: str | None = None,
        *,
        demo_scenario: str | None = None,
    ) -> Path:
        """Run the offline demo scan and write html+json; returns the html path."""
        auth = build_auth_context(mode=AuthMode.DRY_RUN)
        return self._run(
            auth,
            output_dir,
            profile_id,
            dry_run=True,
            demo_scenario=demo_scenario,
        )

    def start_live(
        self,
        output_dir: Path,
        profile_id: str | None = None,
        *,
        auth_mode: AuthMode = AuthMode.DEVICE_CODE,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        oidc_token: str | None = None,
        certificate_path: str | None = None,
        certificate_thumbprint: str | None = None,
    ) -> Path:
        """Run a live-tenant scan with user-supplied auth inputs.

        Device-code sign-ins are captured into the shared state (never
        logged) via the state's prompt callback.
        """
        auth = build_auth_context(
            mode=auth_mode,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            oidc_token=oidc_token,
            certificate_path=certificate_path,
            certificate_thumbprint=certificate_thumbprint,
            device_code_prompt=self.state.device_code_prompt,
        )
        return self._run(
            auth,
            output_dir,
            profile_id,
            dry_run=False,
            demo_scenario=None,
        )

    def run_demo_diff(
        self,
        before_json: Path,
        after_json: Path,
        output: Path | None = None,
    ) -> Path:
        """Diff two scan JSON artifacts into a markdown report."""
        diff_path = write_diff_report(
            before_json,
            after_json,
            output if output is not None else before_json.parent / _DIFF_FILENAME,
        )
        self.state.record_report("diff", diff_path)
        return diff_path

    def _run(
        self,
        auth: AuthContext,
        output_dir: Path,
        profile_id: str | None,
        *,
        dry_run: bool,
        demo_scenario: str | None,
    ) -> Path:
        profile = _resolve_profile(profile_id)
        self.state.set_status("scanning")
        try:
            result = run_scan(
                auth,
                dry_run=dry_run,
                profile=profile,
                demo_scenario=demo_scenario,
                progress=self.state.record_progress,
            )
            scan_dir = _fresh_scan_dir(output_dir)
            html_path = write_html_report(
                result,
                scan_dir / f"{_REPORT_STEM}.html",
                redaction=self._redaction,
            )
            json_path = write_json_report(
                result,
                scan_dir / f"{_REPORT_STEM}.json",
                redaction=self._redaction,
            )
        except Exception:
            self.state.set_status("failed")
            raise
        self.state.record_report("html", html_path)
        self.state.record_report("json", json_path)
        self.state.set_status("complete")
        return html_path
