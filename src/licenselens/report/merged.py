"""Deterministic multi-tenant merged HTML report with a client-side tenant switcher.

``render_merged_html`` inlines each tenant's ``security-license-lens-report.json``
payload into ONE single-file HTML document. The merged view reads a multi-tenant
data shape — ``window.LICENSELENS_TENANTS = {slug: <tenant data>}`` — and a small
inline script swaps the active tenant entirely client-side with zero network
requests (CSP ``default-src 'none'``).

Unlike the report_app v2 bundle entry (``script-src 'self'``), the merged view
adopts ``script-src 'unsafe-inline'`` (matching ``report.html.j2``) and ships its
switcher logic as an inline ``<script>`` block, so the output is a TRUE single
file that opens directly via ``file://``.

Redaction: the UNION of every tenant's redaction targets (tenant ids + UPN
patterns + domains) is applied to every tenant payload through the shared
post-render transform (default ``RedactionSettings``), so the merged artifact
leaks no tenant id or UPN-like string — including cross-tenant identifiers that
appear inside another tenant's region — matching the report redaction default.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Final

from licenselens.config_models import RedactionSettings
from licenselens.report.manifest import escape_data_js
from licenselens.report.redaction import RedactionTargets, redact_text

#: The JSON artifact filename each tenant directory is expected to contain.
REPORT_JSON_FILENAME: Final = "security-license-lens-report.json"

#: The multi-tenant data global the inline switcher reads.
TENANTS_GLOBAL: Final = "window.LICENSELENS_TENANTS"

#: CSP for the merged view — inline script/style, no network, no external assets.
_MERGED_CSP: Final = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'"

#: One UPN-like string: ``local@domain.tld``. Mirrors the redaction module's
#: pattern so tenant domains can be harvested from a raw JSON dict (the merged
#: path reads serialized artifacts, not ``ScanResult`` models).
_UPN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._%*'+-])[A-Za-z0-9._%*'+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)

#: Presentation labels for finding statuses (deterministic, locale-insensitive).
_STATUS_LABELS: Final = {
    "gap": "Action required",
    "partial": "Incomplete",
    "ok": "Operational",
    "not_licensed": "Not licensed",
    "skipped": "Not assessed",
    "error": "Verification failed",
}

_STATUS_ORDER: Final = ["gap", "partial", "ok", "not_licensed", "skipped", "error"]

_SEVERITY_LABELS: Final = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

_SEVERITY_ORDER: Final = ["critical", "high", "medium", "low", "info"]


def render_merged_html(tenant_paths: list[Path], output: Path) -> Path:
    """Inline each tenant's report JSON into one single-file merged HTML.

    Each path is expected to point at a ``security-license-lens-report.json``
    artifact (or a directory containing one). The tenant slug is derived from the
    payload's ``tenant_slug``, falling back to ``tenant_id``, then a stable
    positional index. The output is deterministic (no timestamps) and requires no
    runtime network/fetch. With zero tenant paths an empty-state document is
    rendered rather than raising.
    """
    tenants: dict[str, dict[str, Any]] = {}
    for index, path in enumerate(tenant_paths):
        json_path = _resolve_report_json(path)
        payload = _load_payload(json_path)
        slug = _derive_slug(payload, index, tenants)
        tenants[slug] = payload

    # Redaction is applied to the UNION of every tenant's targets so a
    # cross-tenant identifier (tenant A's id/UPN appearing inside tenant B's
    # payload, or vice versa) is scrubbed from EVERY tenant's region — a
    # per-tenant pass alone would let tenant A's id leak into tenant B's data
    # and back. The union is built from the raw payloads, then applied to each
    # tenant's serialized JSON deterministically.
    union_targets = _union_redaction_targets(tenants.values())
    redacted = {slug: _redact_payload(payload, union_targets) for slug, payload in tenants.items()}

    output.parent.mkdir(parents=True, exist_ok=True)
    html = _render_document(redacted)
    output.write_text(html, encoding="utf-8")
    return output


def _resolve_report_json(path: Path) -> Path:
    """Return the JSON artifact path for a tenant path (file or directory)."""
    if path.is_dir():
        candidate = path / REPORT_JSON_FILENAME
        if not candidate.is_file():
            raise FileNotFoundError(f"tenant directory {path} has no {REPORT_JSON_FILENAME}")
        return candidate
    return path


def _load_payload(path: Path) -> dict[str, Any]:
    """Load and validate a tenant report JSON payload."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"unreadable tenant report {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"tenant report {path} is not a JSON object")
    return raw


def _derive_slug(payload: dict[str, Any], index: int, assigned: dict[str, dict[str, Any]]) -> str:
    """Derive a deterministic, unique tenant slug from the payload.

    Prefers ``tenant_slug``, then ``tenant_id``, then a stable positional index.
    Collisions against already-assigned slugs are disambiguated deterministically
    with a numeric suffix so every tenant keeps a distinct switcher key.
    """
    slug = payload.get("tenant_slug") or payload.get("tenant_id")
    base = str(slug) if slug else f"tenant-{index}"
    candidate = base
    suffix = 2
    while candidate in assigned:
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


def _union_redaction_targets(payloads: list[dict[str, Any]]) -> RedactionTargets:
    """Build the UNION of redaction targets across every tenant payload.

    Tenant ids are harvested from each payload's ``tenant_id``; domains are the
    (lower-cased, de-duplicated) domain parts of every UPN-like string across
    all serialized payloads. Applying this union to every tenant guarantees a
    cross-tenant identifier is scrubbed from every region, not just its own.
    """
    tenant_ids: set[str] = set()
    domains: set[str] = set()
    for payload in payloads:
        tenant_id = payload.get("tenant_id")
        if tenant_id:
            tenant_ids.add(str(tenant_id))
        serialized = json.dumps(payload, ensure_ascii=True, sort_keys=True)
        domains.update(
            match.group(0).partition("@")[2].lower() for match in _UPN_PATTERN.finditer(serialized)
        )
    return RedactionTargets(
        tenant_ids=tuple(sorted(tenant_ids)),
        domains=tuple(sorted(domains)),
    )


def _redact_payload(payload: dict[str, Any], targets: RedactionTargets) -> dict[str, Any]:
    """Apply the shared union redaction transform to a tenant payload."""
    serialized = json.dumps(payload, ensure_ascii=True, sort_keys=True)
    redacted = redact_text(serialized, targets=targets, settings=RedactionSettings())
    return json.loads(redacted)


def _render_document(tenants: dict[str, dict[str, Any]]) -> str:
    """Render the full single-file HTML document for the given tenants."""
    payload_js = escape_data_js(
        json.dumps(tenants, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    )
    if tenants:
        body = _render_tenants_body(tenants)
    else:
        body = _render_empty_state()
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '  <meta charset="utf-8" />\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1" />\n'
        f'  <meta http-equiv="Content-Security-Policy" content="{_MERGED_CSP}" />\n'
        "  <title>Security License Lens — merged tenant view</title>\n"
        "  <style>\n"
        f"{_STYLES}\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        f"{body}\n"
        f"  <script>{TENANTS_GLOBAL} = {payload_js};</script>\n"
        f"  <script>{_SWITCHER_JS}</script>\n"
        "</body>\n"
        "</html>\n"
    )


def _render_tenants_body(tenants: dict[str, dict[str, Any]]) -> str:
    """Render the shell body for a non-empty tenant set (switcher + containers)."""
    slugs = sorted(tenants)
    buttons = "\n".join(
        f'      <button type="button" class="tenant-tab" data-tenant="{_html_escape(slug)}"'
        f' aria-pressed="{"true" if index == 0 else "false"}">{_html_escape(slug)}</button>'
        for index, slug in enumerate(slugs)
    )
    return (
        '  <header class="app-header">\n'
        '    <div class="logo">\n'
        '      <div class="logo-mark" aria-hidden="true"></div>\n'
        "      <div>\n"
        "        <h1>Security License Lens</h1>\n"
        '        <p class="tagline">Merged multi-tenant view — switch tenants below.</p>\n'
        "      </div>\n"
        "    </div>\n"
        "  </header>\n"
        '  <main class="app-main" id="main">\n'
        '    <section aria-labelledby="tenant-switcher-title">\n'
        '      <h2 id="tenant-switcher-title">Tenants</h2>\n'
        '      <div class="tenant-switcher" role="group" aria-label="Switch tenant">\n'
        f"{buttons}\n"
        "      </div>\n"
        "    </section>\n"
        '    <section aria-labelledby="summary-title">\n'
        '      <h2 id="summary-title">Summary</h2>\n'
        '      <div class="tenant-summary" data-tenant-summary></div>\n'
        "    </section>\n"
        '    <section aria-labelledby="findings-title">\n'
        '      <h2 id="findings-title">Findings</h2>\n'
        '      <div class="tenant-findings" data-tenant-findings></div>\n'
        "    </section>\n"
        "  </main>\n"
    )


def _render_empty_state() -> str:
    """Render the empty-state body for a zero-tenant merged view."""
    return (
        '  <header class="app-header">\n'
        '    <div class="logo">\n'
        '      <div class="logo-mark" aria-hidden="true"></div>\n'
        "      <div>\n"
        "        <h1>Security License Lens</h1>\n"
        '        <p class="tagline">Merged multi-tenant view.</p>\n'
        "      </div>\n"
        "    </div>\n"
        "  </header>\n"
        '  <main class="app-main" id="main">\n'
        '    <section aria-labelledby="empty-title">\n'
        '      <h2 id="empty-title">No tenants</h2>\n'
        '      <p class="empty-state">No tenant reports were provided to merge.</p>\n'
        "    </section>\n"
        "  </main>\n"
    )


def _html_escape(value: str) -> str:
    """Escape a string for safe interpolation into HTML text/attribute context."""
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


# ---------------------------------------------------------------------------
# Inline stylesheet — self-contained, no external assets.
# ---------------------------------------------------------------------------

_STYLES = """
:root {
  color-scheme: light dark;
  --bg: #ffffff;
  --text: #1a1a1a;
  --text-2: #5a5a5a;
  --accent: #2563eb;
  --surface: #f4f4f5;
  --border: #d4d4d8;
  --gap: #dc2626;
  --partial: #d97706;
  --ok: #16a34a;
  --not_licensed: #6b7280;
  --skipped: #6b7280;
  --error: #7c3aed;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f172a;
    --text: #e2e8f0;
    --text-2: #94a3b8;
    --surface: #1e293b;
    --border: #334155;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
}
.app-header { border-bottom: 1px solid var(--border); padding: 16px 24px; }
.logo { display: flex; align-items: center; gap: 12px; }
.logo-mark {
  width: 28px; height: 28px; background: var(--accent);
  border-radius: 2px; flex-shrink: 0;
}
.logo h1 { margin: 0; font-size: 1.25rem; }
.tagline { margin: 0; color: var(--text-2); font-size: 0.8125rem; }
.app-main { max-width: 960px; margin: 0 auto; padding: 24px; }
section { margin-block-end: 32px; }
h2 { font-size: 1.125rem; margin-block: 0 12px; }
.tenant-switcher { display: flex; flex-wrap: wrap; gap: 8px; }
.tenant-tab {
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text);
  border-radius: 6px;
  padding: 8px 14px;
  font: inherit;
  cursor: pointer;
}
.tenant-tab[aria-pressed="true"] {
  background: var(--accent);
  border-color: var(--accent);
  color: #ffffff;
}
.tenant-tab:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}
.tenant-summary, .tenant-findings { display: grid; gap: 12px; }
.card {
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  background: var(--surface);
}
.card h3 { margin: 0 0 8px; font-size: 1rem; }
.stat-strip { display: flex; flex-wrap: wrap; gap: 8px 24px; margin-block-end: 12px; }
.stat { display: inline-flex; gap: 6px; align-items: baseline; }
.stat__num { font-weight: 700; font-size: 1.25rem; }
.stat__label { color: var(--text-2); font-size: 0.8125rem; }
.status-marker {
  display: inline-flex; align-items: center; gap: 6px;
  border-radius: 999px; padding: 2px 10px;
  font-size: 0.75rem; font-weight: 600;
}
.status-marker.gap {
  background: color-mix(in srgb, var(--gap) 18%, transparent); color: var(--gap);
}
.status-marker.partial {
  background: color-mix(in srgb, var(--partial) 18%, transparent); color: var(--partial);
}
.status-marker.ok {
  background: color-mix(in srgb, var(--ok) 18%, transparent); color: var(--ok);
}
.status-marker.not_licensed, .status-marker.skipped {
  background: color-mix(in srgb, var(--not_licensed) 18%, transparent); color: var(--text-2);
}
.status-marker.error {
  background: color-mix(in srgb, var(--error) 18%, transparent); color: var(--error);
}
.finding {
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px 16px;
  background: var(--bg);
}
.finding-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.finding-head h3 { margin: 0; font-size: 0.95rem; flex: 1 1 auto; }
.finding-meta {
  display: flex; flex-wrap: wrap; gap: 4px 16px;
  color: var(--text-2); font-size: 0.8125rem; margin-block: 6px 0;
}
.finding-summary { margin: 8px 0 0; }
.empty-state { color: var(--text-2); }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.8125rem; }
"""


# ---------------------------------------------------------------------------
# Inline switcher script — renders the active tenant's summary + findings
# entirely client-side from window.LICENSELENS_TENANTS. No fetch, no eval,
# no inline event handlers; dynamic text is inserted via createTextNode.
# ---------------------------------------------------------------------------

_SWITCHER_JS = r"""
(function () {
  "use strict";

  var tenants = window.LICENSELENS_TENANTS || {};
  var slugs = Object.keys(tenants).sort();

  var STATUS_LABELS = {
    gap: "Action required", partial: "Incomplete", ok: "Operational",
    not_licensed: "Not licensed", skipped: "Not assessed", error: "Verification failed"
  };
  var STATUS_ORDER = ["gap", "partial", "ok", "not_licensed", "skipped", "error"];
  var SEVERITY_LABELS = {
    critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info"
  };
  var SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

  function el(tag, className) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    return node;
  }
  function text(value) {
    return document.createTextNode(value == null ? "" : String(value));
  }
  function cap(value) {
    if (!value) return "";
    return String(value).charAt(0).toUpperCase() + String(value).slice(1);
  }
  function firstStr() {
    for (var i = 0; i < arguments.length; i++) {
      var v = arguments[i];
      if (v) return String(v);
    }
    return "";
  }
  function rankOf(order, value) {
    var idx = order.indexOf(value);
    return idx === -1 ? order.length : idx;
  }

  function statusMarker(status, label) {
    var marker = el("span", "status-marker " + status);
    marker.appendChild(text(label));
    return marker;
  }

  function findingMeta(f) {
    var meta = el("div", "finding-meta");
    var parts = [];
    if (f.severity) parts.push("Severity: " + (SEVERITY_LABELS[f.severity] || cap(f.severity)));
    if (f.confidence_label) parts.push("Confidence: " + f.confidence_label);
    if (f.evaluation_mode) parts.push("Mode: " + cap(f.evaluation_mode));
    if (f.effort) parts.push("Effort: " + cap(f.effort));
    if (f.workload) parts.push("Workload: " + cap(f.workload));
    parts.forEach(function (p, i) {
      if (i > 0) meta.appendChild(text(" · "));
      meta.appendChild(text(p));
    });
    return meta;
  }

  function renderFinding(f) {
    var status = f.status || "error";
    var title = firstStr(f.title, f.customer_title, f.check_id);
    var article = el("article", "finding " + status);
    var head = el("div", "finding-head");
    head.appendChild(statusMarker(status, STATUS_LABELS[status] || status));
    var h3 = el("h3");
    h3.appendChild(text(title));
    head.appendChild(h3);
    article.appendChild(head);

    var meta = findingMeta(f);
    if (meta.childNodes.length) article.appendChild(meta);

    var summary = firstStr(f.customer_summary, f.summary);
    if (summary) {
      var p = el("p", "finding-summary");
      p.appendChild(text(summary));
      article.appendChild(p);
    }
    if (f.customer_next_step) {
      var action = el("p", "finding-summary");
      var strong = el("strong");
      strong.appendChild(text("Action: "));
      action.appendChild(strong);
      action.appendChild(text(f.customer_next_step));
      article.appendChild(action);
    }
    if (f.check_id) {
      var id = el("p", "finding-meta");
      id.appendChild(text("Check: "));
      var code = el("code", "mono");
      code.appendChild(text(f.check_id));
      id.appendChild(code);
      article.appendChild(id);
    }
    return article;
  }

  function countByStatus(findings) {
    var counts = {};
    STATUS_ORDER.forEach(function (s) { counts[s] = 0; });
    (findings || []).forEach(function (f) {
      var s = f.status || "error";
      if (counts[s] !== undefined) counts[s] += 1;
    });
    return counts;
  }

  function renderSummary(tenant) {
    var wrap = el("div", "card");
    var h3 = el("h3");
    h3.appendChild(text("Posture"));
    wrap.appendChild(h3);

    var rollup = tenant.capability_rollup || {};
    var realized = rollup.realized_percent;
    var statStrip = el("div", "stat-strip");
    var stats = [
      ["Realized", (realized == null ? "—" : realized + "%")],
      ["You own", rollup.you_own == null ? "—" : rollup.you_own],
      ["Fully working", rollup.fully_working == null ? "—" : rollup.fully_working],
      ["Need attention", rollup.needs_attention == null ? "—" : rollup.needs_attention],
      ["Partly set up", rollup.partly_set_up == null ? "—" : rollup.partly_set_up],
      ["Not in plan", rollup.not_licensed == null ? "—" : rollup.not_licensed]
    ];
    stats.forEach(function (pair) {
      var stat = el("span", "stat");
      var num = el("span", "stat__num");
      num.appendChild(text(String(pair[1])));
      var label = el("span", "stat__label");
      label.appendChild(text(pair[0]));
      stat.appendChild(num);
      stat.appendChild(label);
      statStrip.appendChild(stat);
    });
    wrap.appendChild(statStrip);

    var findings = tenant.findings || [];
    var counts = countByStatus(findings);
    var countLine = el("p");
    countLine.appendChild(text("Findings: " + findings.length + " total."));
    wrap.appendChild(countLine);

    var gaps = findings.filter(function (f) {
      return f.status === "gap" || f.status === "partial";
    }).sort(function (a, b) {
      var diff = rankOf(SEVERITY_ORDER, String(a.severity || "")) -
        rankOf(SEVERITY_ORDER, String(b.severity || ""));
      if (diff !== 0) return diff;
      return String(a.check_id || "").localeCompare(String(b.check_id || ""));
    }).slice(0, 5);

    if (gaps.length) {
      var top = el("div");
      var topLabel = el("strong");
      topLabel.appendChild(text("Top gaps:"));
      top.appendChild(topLabel);
      var list = el("ul");
      gaps.forEach(function (g) {
        var li = el("li");
        li.appendChild(text(firstStr(g.title, g.check_id)));
        list.appendChild(li);
      });
      top.appendChild(list);
      wrap.appendChild(top);
    }
    return wrap;
  }

  function renderFindings(tenant) {
    var wrap = el("div");
    var findings = (tenant.findings || []).slice().sort(function (a, b) {
      var diff = rankOf(SEVERITY_ORDER, String(a.severity || "")) -
        rankOf(SEVERITY_ORDER, String(b.severity || ""));
      if (diff !== 0) return diff;
      diff = rankOf(STATUS_ORDER, String(a.status || "")) -
        rankOf(STATUS_ORDER, String(b.status || ""));
      if (diff !== 0) return diff;
      return String(a.check_id || "").localeCompare(String(b.check_id || ""));
    });
    if (!findings.length) {
      var empty = el("p", "empty-state");
      empty.appendChild(text("No findings for this tenant."));
      wrap.appendChild(empty);
      return wrap;
    }
    findings.forEach(function (f) { wrap.appendChild(renderFinding(f)); });
    return wrap;
  }

  function renderActive(slug) {
    var tenant = tenants[slug];
    if (!tenant) return;
    var summaryEl = document.querySelector("[data-tenant-summary]");
    var findingsEl = document.querySelector("[data-tenant-findings]");
    if (summaryEl) {
      summaryEl.textContent = "";
      summaryEl.appendChild(renderSummary(tenant));
    }
    if (findingsEl) {
      findingsEl.textContent = "";
      findingsEl.appendChild(renderFindings(tenant));
    }
    var tabs = document.querySelectorAll(".tenant-tab");
    Array.prototype.forEach.call(tabs, function (tab) {
      tab.setAttribute("aria-pressed", tab.getAttribute("data-tenant") === slug ? "true" : "false");
    });
  }

  function init() {
    if (!slugs.length) return;
    var tabs = document.querySelectorAll(".tenant-tab");
    Array.prototype.forEach.call(tabs, function (tab) {
      tab.addEventListener("click", function () {
        renderActive(tab.getAttribute("data-tenant"));
      });
    });
    renderActive(slugs[0]);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
"""


__all__ = ["render_merged_html"]
