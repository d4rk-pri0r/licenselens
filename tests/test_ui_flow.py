"""End-to-end wizard HTTP flow (T12)."""

from __future__ import annotations

import threading
import time
from http.client import HTTPConnection
from pathlib import Path
from urllib.parse import urlencode

import pytest

from licenselens.cli_profile_info import profile_requirement_report
from licenselens.ui.pages import serve_wizard
from licenselens.ui.server import WizardHTTPServer


def _start(tmp_path: Path) -> tuple[WizardHTTPServer, int]:
    server = serve_wizard("127.0.0.1", 0, tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def _stop(server: WizardHTTPServer) -> None:
    server.shutdown()
    server.server_close()


def _get(
    port: int,
    path: str,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    conn = HTTPConnection("127.0.0.1", port, timeout=30)
    hdrs = {"Host": f"127.0.0.1:{port}"}
    if headers:
        hdrs.update(headers)
    conn.request("GET", path, headers=hdrs)
    response = conn.getresponse()
    body = response.read()
    header_map = {k.lower(): v for k, v in response.getheaders()}
    conn.close()
    return response.status, body, header_map


def _post(
    port: int,
    path: str,
    csrf: str,
    extra: dict[str, str] | None = None,
) -> tuple[int, bytes, str | None]:
    fields = {"csrf": csrf}
    if extra:
        fields.update(extra)
    body = urlencode(fields)
    conn = HTTPConnection("127.0.0.1", port, timeout=30)
    conn.request(
        "POST",
        path,
        body=body,
        headers={
            "Host": f"127.0.0.1:{port}",
            "Origin": f"http://127.0.0.1:{port}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body)),
        },
    )
    response = conn.getresponse()
    payload = response.read()
    location = response.getheader("Location")
    conn.close()
    return response.status, payload, location


def test_demo_flow_serves_report(tmp_path: Path) -> None:
    server, port = _start(tmp_path)
    try:
        status, index, _ = _get(port, "/")
        assert status == 200
        assert b"core" in index
        expected = str(len(profile_requirement_report("core").check_ids)).encode()
        assert expected in index
        csrf = server.csrf_token
        status, _, location = _post(port, "/demo", csrf, {"profile": "core"})
        assert status in {200, 303}
        assert location in {None, "/scan"}
        deadline = time.time() + 60
        report_status = 404
        body = b""
        while time.time() < deadline:
            progress_status, progress_body, _ = _get(port, "/progress")
            assert progress_status == 200
            report_status, body, _ = _get(port, "/report")
            if report_status == 200 and (
                b"Security License Lens" in body or b"licenselens" in body.lower()
            ):
                break
            time.sleep(0.4)
        assert report_status == 200, progress_body
        assert b"html" in body.lower() or b"License" in body or b"report" in body.lower()
    finally:
        _stop(server)


def test_progress_surfaces_events(tmp_path: Path) -> None:
    server, port = _start(tmp_path)
    try:
        _post(port, "/demo", server.csrf_token, {"profile": "core"})
        deadline = time.time() + 60
        events = b""
        while time.time() < deadline:
            _, events, _ = _get(port, "/progress")
            if b"collector_id" in events and b"total" in events:
                break
            time.sleep(0.3)
        assert b"collector_id" in events
    finally:
        _stop(server)


def test_report_query_path_is_forbidden(tmp_path: Path) -> None:
    server, port = _start(tmp_path)
    try:
        status, _, _ = _get(port, "/report?path=../../etc/passwd")
        assert status in {403, 404}
    finally:
        _stop(server)


def test_index_serves_real_form_and_button(tmp_path: Path) -> None:
    server, port = _start(tmp_path)
    try:
        status, index, _ = _get(port, "/")
        assert status == 200
        assert b"<form" in index
        assert b"<button" in index
        assert b"&lt;form" not in index
        assert b"Run the offline demo" in index
    finally:
        _stop(server)


def test_hostile_profile_name_is_escaped(tmp_path: Path) -> None:
    from licenselens.ui.pages import WizardApp

    app = WizardApp(tmp_path)
    html = app.render(
        "mode.html",
        csrf="token",
        profiles=[
            {
                "id": "core",
                "name": "<img src=x onerror=alert(1)>Collaboration",
                "checks": 1,
            }
        ],
        default="core",
        core_summary="<script>alert(1)</script>core covers 0 checks",
    )
    text = html.decode("utf-8")
    assert "<form" in text
    assert "<button" in text
    assert "<img src=x onerror=alert(1)>" not in text
    assert "&lt;img src=x onerror=alert(1)&gt;" in text
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text


@pytest.mark.browser
def test_browser_clicks_demo_button(tmp_path: Path) -> None:
    """Real browser: the advertised demo button is a real control and yields a report."""
    from playwright.sync_api import sync_playwright

    server, port = _start(tmp_path)
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page()
            page.goto(f"http://127.0.0.1:{port}/")
            assert page.locator("form").count() >= 1
            assert page.locator("button[type=submit]").count() >= 1
            page.get_by_role("button", name="Run the offline demo").click()
            page.wait_for_selector("#status", timeout=15_000)
            deadline = time.time() + 60
            report_ok = False
            body = ""
            while time.time() < deadline:
                resp = page.request.get(f"http://127.0.0.1:{port}/report")
                body = resp.text() if resp.status == 200 else ""
                if resp.status == 200 and (
                    "Security License Lens" in body or "licenselens" in body.lower()
                ):
                    report_ok = True
                    break
                time.sleep(0.4)
            browser.close()
            assert report_ok, body[:500]
    finally:
        _stop(server)
