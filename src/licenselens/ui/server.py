"""Loopback-only HTTP server for the local ui wizard.

Binds 127.0.0.1 / localhost only. Host, Origin, and CSRF checks run before
any action. Wizard pages are added in T12; this module is the security core.
"""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Final
from urllib.parse import urlparse

LOOPBACK_HOSTS: Final[frozenset[str]] = frozenset({"127.0.0.1", "localhost", "::1"})

CSP: Final = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'self'"
)

SECURITY_HEADERS: Final[tuple[tuple[str, str], ...]] = (
    ("Content-Security-Policy", CSP),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
)

ActionHandler = Callable[["WizardHandler"], None]


def validate_bind_host(host: str) -> str:
    """Return ``host`` if it is loopback; otherwise raise ValueError."""
    if host not in LOOPBACK_HOSTS:
        raise ValueError(f"ui server refuses non-loopback host {host!r}")
    return host


def _host_from_header(value: str | None) -> str | None:
    if not value:
        return None
    parsed = urlparse(f"//{value.strip()}")
    return (parsed.hostname or "").lower() or None


class WizardHandler(BaseHTTPRequestHandler):
    """Request handler with Host / Origin / CSRF guards."""

    server: WizardHTTPServer  # type: ignore[assignment]
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        # Never log request lines — they can carry device codes or tokens.
        return

    def _send(
        self,
        status: int,
        body: bytes,
        *,
        content_type: str = "text/html; charset=utf-8",
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _forbidden(self, reason: str = "forbidden") -> None:
        self._send(403, reason.encode("utf-8"), content_type="text/plain; charset=utf-8")

    def _not_found(self) -> None:
        self._send(404, b"not found", content_type="text/plain; charset=utf-8")

    def _host_ok(self) -> bool:
        host = _host_from_header(self.headers.get("Host"))
        return host in LOOPBACK_HOSTS

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin") or self.headers.get("Referer")
        if not origin:
            return True
        parsed = urlparse(origin)
        if parsed.hostname not in LOOPBACK_HOSTS:
            return False
        expected_port = self.server.server_address[1]
        if parsed.port is None:
            return expected_port in {80, 443}
        return parsed.port == expected_port

    def _csrf_ok(self, raw: bytes) -> bool:
        from urllib.parse import parse_qs

        fields = parse_qs(raw.decode("utf-8", errors="replace"), keep_blank_values=True)
        submitted = (fields.get("csrf") or [""])[0]
        return hmac.compare_digest(submitted, self.server.csrf_token)

    def do_GET(self) -> None:  # noqa: N802
        if not self._host_ok():
            self._forbidden("bad host")
            return
        path = urlparse(self.path).path
        handler = self.server.get_routes.get(path)
        if handler is None:
            self._not_found()
            return
        handler(self)

    def do_POST(self) -> None:  # noqa: N802
        if not self._host_ok():
            self._forbidden("bad host")
            return
        if not self._origin_ok():
            self._forbidden("bad origin")
            return
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length) if length > 0 else b""
        if not self._csrf_ok(raw):
            self._forbidden("bad csrf")
            return
        path = urlparse(self.path).path
        handler = self.server.post_routes.get(path)
        if handler is None:
            self._not_found()
            return
        self._post_body = raw
        handler(self)

    def stub_index(self) -> None:
        token = self.server.csrf_token
        html = (
            "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
            "<title>LicenseLens</title></head><body>"
            f"<p>LicenseLens local wizard</p>"
            f"<form method='post' action='/stub'><input type='hidden' name='csrf' value='{token}'>"
            "<button type='submit'>ok</button></form></body></html>"
        )
        self._send(200, html.encode("utf-8"))

    def stub_post(self) -> None:
        self._send(200, b"ok", content_type="text/plain; charset=utf-8")


class WizardHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server bound to loopback only."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        host: str,
        port: int,
        *,
        csrf_token: str | None = None,
        get_routes: dict[str, ActionHandler] | None = None,
        post_routes: dict[str, ActionHandler] | None = None,
        handler_class: type[WizardHandler] = WizardHandler,
    ) -> None:
        validate_bind_host(host)
        self.csrf_token = csrf_token or secrets.token_urlsafe(32)
        super().__init__((host, port), handler_class)
        self.get_routes: dict[str, ActionHandler] = get_routes or {
            "/": WizardHandler.stub_index,
        }
        self.post_routes: dict[str, ActionHandler] = post_routes or {
            "/stub": WizardHandler.stub_post,
        }


def serve(
    host: str = "127.0.0.1",
    port: int = 8765,
    **kwargs: Any,
) -> WizardHTTPServer:
    """Construct a loopback server. Bind failures propagate to the caller."""
    return WizardHTTPServer(host, port, **kwargs)
