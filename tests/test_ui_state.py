"""Tests for the local ui scan session state (T5, TDD).

Covers: offline demo session artifacts, ordered progress capture, the
``core`` default profile, the house ``ScanConfigError`` on unknown
profiles, demo diff output, device-code silence, and thread safety.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from licenselens.cli_scan_config import ScanConfigError
from licenselens.collectors.contracts import (
    CollectionMetadata,
    EvidenceEnvelope,
    EvidenceHealth,
    EvidenceKey,
)
from licenselens.ui.state import ScanSession, UiState


def test_demo_session_writes_html_and_json_into_fresh_subdir(tmp_path: Path) -> None:
    session = ScanSession()
    html_path = session.start_demo(tmp_path)
    assert html_path.is_file()
    assert html_path.name == "security-license-lens-report.html"
    assert html_path.parent.name.startswith("scan-")
    json_path = html_path.with_suffix(".json")
    assert json_path.is_file()
    assert session.state.status == "complete"


def test_progress_events_recorded_in_order_with_sane_totals(tmp_path: Path) -> None:
    session = ScanSession()
    session.start_demo(tmp_path)
    events = session.state.snapshot_progress()
    assert events, "expected at least one progress event from the demo scan"
    assert [event.index for event in events] == list(range(len(events)))
    assert {event.total for event in events} == {len(events)}
    assert all(event.collector_id for event in events)
    assert all(event.items >= 0 for event in events)
    assert all(
        event.status in {"success", "partial", "failed", "skipped", "unsupported"}
        for event in events
    )


def test_default_profile_is_core(tmp_path: Path) -> None:
    session = ScanSession()
    html_path = session.start_demo(tmp_path)
    payload = json.loads(html_path.with_suffix(".json").read_text(encoding="utf-8"))
    assert payload["profile_ids"] == ["core"]


def test_invalid_profile_raises_scan_config_error(tmp_path: Path) -> None:
    session = ScanSession()
    with pytest.raises(ScanConfigError):
        session.start_demo(tmp_path, profile_id="no-such-profile")


def test_demo_diff_writes_markdown_from_two_artifacts(tmp_path: Path) -> None:
    session = ScanSession()
    before_html = session.start_demo(tmp_path / "before")
    after_html = session.start_demo(tmp_path / "after", demo_scenario="after")
    diff_path = session.run_demo_diff(
        before_html.with_suffix(".json"),
        after_html.with_suffix(".json"),
    )
    assert diff_path.suffix == ".md"
    assert diff_path.is_file()
    assert diff_path.read_text(encoding="utf-8").strip()


def test_device_code_capture_is_silent(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    session = ScanSession()
    user_code = "SECRET-DEVICE-CODE-9"
    session.state.device_code_prompt(
        "https://microsoft.com/devicelogin", user_code, datetime.now(UTC)
    )
    with caplog.at_level(logging.DEBUG):
        session.start_demo(tmp_path)
    assert user_code not in caplog.text
    captured = capsys.readouterr()
    assert user_code not in captured.out
    assert user_code not in captured.err
    stored = session.state.snapshot_device_code()
    assert stored is not None
    assert stored[0] == "https://microsoft.com/devicelogin"
    assert stored[1] == user_code


def test_record_progress_is_thread_safe() -> None:
    state = UiState()
    total_steps = 50
    workers = 4

    def record(worker: int) -> None:
        for index in range(total_steps):
            envelope = EvidenceEnvelope(
                key=EvidenceKey(f"key-{worker}-{index}"),
                health=EvidenceHealth.OK,
                metadata=CollectionMetadata(items_collected=index),
            )
            state.record_progress(f"collector-{worker}", index, total_steps, envelope)

    threads = [
        threading.Thread(target=record, args=(worker,)) for worker in range(workers)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(state.snapshot_progress()) == workers * total_steps
