"""Loopback ui server security core (T8)."""

from __future__ import annotations

import threading
from http.client import HTTPConnection
from urllib.parse import urlencode

import pytest

from licenselens.ui.server import LOOPBACK_HOSTS, WizardHTTPServer, serve, validate_bind_host


def _start(host: str = "127.0.0.1") -> tuple[WizardHTTPServer, int, threading.Thread]:
    server = serve(host, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    return server, port, thread


def _stop(server: WizardHTTPServer) -> None:
    server.shutdown()
    server.server_close()


def test_non_loopback_hosts_raise() -> None:
    for host in ("0.0.0.0", "::", "192.168.1.5", "example.com"):
        with pytest.raises(ValueError, match="non-loopback"):
            validate_bind_host(host)
        with pytest.raises(ValueError, match="non-loopback"):
            serve(host, 0)


def test_forged_host_header_is_403() -> None:
    server, port, _ = _start()
    try:
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/", headers={"Host": "evil.example"})
        response = conn.getresponse()
        assert response.status == 403
        conn.close()
    finally:
        _stop(server)


def test_mismatched_origin_post_is_403() -> None:
    server, port, _ = _start()
    try:
        body = urlencode({"csrf": server.csrf_token})
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request(
            "POST",
            "/stub",
            body=body,
            headers={
                "Host": f"127.0.0.1:{port}",
                "Origin": "https://evil.example",
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(body)),
            },
        )
        response = conn.getresponse()
        assert response.status == 403
        conn.close()
    finally:
        _stop(server)


def test_null_origin_with_csrf_is_accepted() -> None:
    """Chromium sends Origin: null under Referrer-Policy: no-referrer."""
    server, port, _ = _start()
    try:
        body = urlencode({"csrf": server.csrf_token})
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request(
            "POST",
            "/stub",
            body=body,
            headers={
                "Host": f"127.0.0.1:{port}",
                "Origin": "null",
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(body)),
            },
        )
        assert conn.getresponse().status == 200
        conn.close()
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request(
            "POST",
            "/stub",
            body=urlencode({"csrf": "wrong"}),
            headers={
                "Host": f"127.0.0.1:{port}",
                "Origin": "null",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        assert conn.getresponse().status == 403
        conn.close()
    finally:
        _stop(server)


def test_csrf_required_on_post() -> None:
    server, port, _ = _start()
    try:
        headers = {
            "Host": f"127.0.0.1:{port}",
            "Origin": f"http://127.0.0.1:{port}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/stub", body=urlencode({}), headers=headers)
        assert conn.getresponse().status == 403
        conn.close()

        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        bad = urlencode({"csrf": "not-the-token"})
        conn.request("POST", "/stub", body=bad, headers=headers)
        assert conn.getresponse().status == 403
        conn.close()

        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        good = urlencode({"csrf": server.csrf_token})
        conn.request("POST", "/stub", body=good, headers=headers)
        assert conn.getresponse().status == 200
        conn.close()
    finally:
        _stop(server)


def test_csp_header_on_index() -> None:
    server, port, _ = _start()
    try:
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/", headers={"Host": f"127.0.0.1:{port}"})
        response = conn.getresponse()
        assert response.status == 200
        csp = response.getheader("Content-Security-Policy") or ""
        assert "default-src 'none'" in csp
        assert "script-src 'self'" in csp
        assert response.getheader("X-Content-Type-Options") == "nosniff"
        assert response.getheader("Referrer-Policy") == "no-referrer"
        assert response.getheader("Cache-Control") == "no-store"
        conn.close()
    finally:
        _stop(server)


def test_shutdown_is_clean() -> None:
    server, _port, thread = _start()
    _stop(server)
    thread.join(timeout=2)
    assert not thread.is_alive()


def test_loopback_hosts_are_accepted() -> None:
    for host in LOOPBACK_HOSTS - {"::1"}:
        assert validate_bind_host(host) == host
