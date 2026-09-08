"""Server-rendered wizard pages for the local ui (inline Jinja, no extra assets)."""

from __future__ import annotations

import json
import threading
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from jinja2 import DictLoader, Environment, select_autoescape

from licenselens.cli_profile_info import profile_requirement_report
from licenselens.engine.profiles import load_builtin_profiles
from licenselens.ui.server import WizardHandler, WizardHTTPServer, serve
from licenselens.ui.state import DEFAULT_PROFILE_ID, ScanSession, UiState

_ENV = Environment(
    autoescape=select_autoescape(["html"]),
    loader=DictLoader(
        {
            "shell.html": """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>LicenseLens</title>
  <link rel="stylesheet" href="/app.css">
</head>
<body>
  <main>
    <h1>LicenseLens</h1>
    {% include page %}
  </main>
  <script src="/app.js"></script>
</body>
</html>
""",
            "mode.html": """
<p>Read-only. Nothing leaves this computer. No account, no telemetry.</p>
<form method="post" action="/demo">
  <input type="hidden" name="csrf" value="{{ csrf }}">
  <label>Scan profile
    <select name="profile">
    {% for p in profiles %}
      <option value="{{ p.id }}" {% if p.id == default %}selected{% endif %}>
        {{ p.name }} — {{ p.checks }} checks
      </option>
    {% endfor %}
    </select>
  </label>
  <p>{{ core_summary }}</p>
  <button type="submit">Run the offline demo</button>
</form>
<p>Live tenant sign-in is chosen after you confirm what this tool reads.
Use <code>licenselens quickstart</code> for a live scan from the terminal tonight
(0.3.0). The live wizard path ships with 0.4.0.</p>
""",
            "scan.html": """
<p id="status">Scanning…</p>
<pre id="progress"></pre>
<p><a href="/report">Open the report</a> when the scan finishes.</p>
<form method="post" action="/diff">
  <input type="hidden" name="csrf" value="{{ csrf }}">
  <button type="submit">Run the after-fix demo and show the diff (0.4.0+)</button>
</form>
""",
            "done.html": """
<p>Scan complete.</p>
<p><a href="/report">Open the HTML report</a></p>
{% if diff %}
<p><a href="/diff-report">Open the diff</a></p>
{% endif %}
""",
        }
    ),
)

APP_CSS = (
    "body { font-family: ui-sans-serif, system-ui, sans-serif; "
    "background: #0f1114; color: #f2f4f7; margin: 2rem; }\n"
    "a { color: #88b4d8; }\n"
    "button, select { font: inherit; }\n"
    "main { max-width: 40rem; }\n"
    "pre { white-space: pre-wrap; }\n"
)

APP_JS = """
async function poll() {
  const el = document.getElementById('progress');
  const status = document.getElementById('status');
  if (!el) return;
  const res = await fetch('/progress');
  if (!res.ok) return;
  const data = await res.json();
  if (status) status.textContent = data.status || '';
  el.textContent = (data.events || []).map(
    (e) => e.index + '/' + e.total + ' ' + e.collector_id + ' ' + e.status
  ).join('\\n');
  if (data.status === 'complete' || data.status === 'failed') return;
  setTimeout(poll, 400);
}
if (document.getElementById('progress')) poll();
"""


def _profile_choices() -> list[dict[str, Any]]:
    choices: list[dict[str, Any]] = []
    for profile in load_builtin_profiles():
        report = profile_requirement_report(str(profile.id))
        choices.append(
            {
                "id": str(profile.id),
                "name": profile.name,
                "checks": len(report.check_ids),
            }
        )
    return choices


def _core_summary() -> str:
    report = profile_requirement_report(DEFAULT_PROFILE_ID)
    caps = ", ".join(report.capabilities[:8])
    return (
        f"{DEFAULT_PROFILE_ID} covers {len(report.check_ids)} checks "
        f"across {caps or 'identity and endpoint'}."
    )


class WizardApp:
    """Wires wizard routes onto the loopback server."""

    def __init__(self, output_dir: Path, *, profile_id: str | None = None) -> None:
        self.output_dir = output_dir
        self.default_profile = profile_id or DEFAULT_PROFILE_ID
        self.state = UiState()
        self.session = ScanSession(self.state)
        self._lock = threading.Lock()
        self._worker: threading.Thread | None = None

    def render(self, name: str, **ctx: Any) -> bytes:
        # Compose via {% include %} so autoescape runs once. Rendering the
        # inner template to a string and interpolating it as {{ body }}
        # double-escapes the markup into visible text (zero real forms).
        html = _ENV.get_template("shell.html").render(page=name, **ctx)
        return html.encode("utf-8")

    def attach(self, server: WizardHTTPServer) -> None:
        server.get_routes = {
            "/": self.handle_index,
            "/app.css": self.handle_css,
            "/app.js": self.handle_js,
            "/scan": self.handle_scan_page,
            "/progress": self.handle_progress,
            "/report": self.handle_report,
            "/diff-report": self.handle_diff_report,
        }
        server.post_routes = {
            "/demo": self.handle_start_demo,
            "/diff": self.handle_diff,
        }

    def handle_index(self, handler: WizardHandler) -> None:
        body = self.render(
            "mode.html",
            csrf=handler.server.csrf_token,
            profiles=_profile_choices(),
            default=self.default_profile,
            core_summary=_core_summary(),
        )
        handler._send(200, body)

    def handle_css(self, handler: WizardHandler) -> None:
        handler._send(200, APP_CSS.encode("utf-8"), content_type="text/css; charset=utf-8")

    def handle_js(self, handler: WizardHandler) -> None:
        handler._send(
            200, APP_JS.encode("utf-8"), content_type="application/javascript; charset=utf-8"
        )

    def handle_scan_page(self, handler: WizardHandler) -> None:
        handler._send(200, self.render("scan.html", csrf=handler.server.csrf_token))

    def handle_progress(self, handler: WizardHandler) -> None:
        payload = {
            "status": self.state.status,
            "events": [
                {
                    "collector_id": event.collector_id,
                    "index": event.index,
                    "total": event.total,
                    "status": event.status,
                    "items": event.items,
                }
                for event in self.state.snapshot_progress()
            ],
        }
        handler._send(
            200,
            json.dumps(payload).encode("utf-8"),
            content_type="application/json; charset=utf-8",
        )

    def _safe_session_file(self, name: str) -> Path | None:
        paths = self.state.snapshot_report_paths()
        raw = paths.get(name)
        if not raw:
            return None
        path = Path(raw).resolve()
        root = self.output_dir.resolve()
        if root not in path.parents and path.parent != root:
            return None
        return path if path.is_file() else None

    def handle_report(self, handler: WizardHandler) -> None:
        query = parse_qs(urlparse(handler.path).query)
        if "path" in query:
            handler._forbidden("bad path")
            return
        html_path = self._safe_session_file("html")
        if html_path is None:
            handler._not_found()
            return
        handler._send(200, html_path.read_bytes())

    def handle_diff_report(self, handler: WizardHandler) -> None:
        diff_path = self._safe_session_file("diff")
        if diff_path is None:
            handler._not_found()
            return
        handler._send(
            200,
            diff_path.read_bytes(),
            content_type="text/markdown; charset=utf-8",
        )

    def handle_start_demo(self, handler: WizardHandler) -> None:
        fields = parse_qs(handler._post_body.decode("utf-8", errors="replace"))
        profile = (fields.get("profile") or [self.default_profile])[0]
        self.default_profile = profile

        def _run() -> None:
            self.session.start_demo(self.output_dir, profile)

        with self._lock:
            if self._worker is None or not self._worker.is_alive():
                self.state.set_status("scanning")
                self._worker = threading.Thread(target=_run, daemon=True)
                self._worker.start()
        handler.send_response(303)
        handler.send_header("Location", "/scan")
        handler.send_header("Content-Length", "0")
        handler.send_header("Connection", "close")
        handler.send_header("Cache-Control", "no-store")
        handler.end_headers()

    def handle_diff(self, handler: WizardHandler) -> None:
        before = self.session.start_demo(self.output_dir, self.default_profile)
        after = self.session.start_demo(
            self.output_dir, self.default_profile, demo_scenario="after"
        )
        before_json = before.with_suffix(".json")
        after_json = after.with_suffix(".json")
        self.session.run_demo_diff(before_json, after_json)
        handler._send(200, self.render("done.html", diff=True, csrf=handler.server.csrf_token))


def serve_wizard(
    host: str,
    port: int,
    output_dir: Path,
    *,
    profile_id: str | None = None,
) -> WizardHTTPServer:
    app = WizardApp(output_dir, profile_id=profile_id)
    server = serve(host, port)
    app.attach(server)
    server.wizard_app = app  # type: ignore[attr-defined]
    return server


def html_escape(value: str) -> str:
    return escape(value, quote=True)
