/* Versioned offline report application (report app v2, DESIGN_V2 "Warm Charcoal").
 *
 * Everything is rendered client-side from the escaped data assets
 * ``window.LICENSELENS_REPORT_JSON``, ``window.LICENSELENS_VIEWMODEL`` and
 * ``window.LICENSELENS_WORKLOAD_ICONS``. No ``fetch``, no ``eval``, no inline
 * event handlers, no third-party runtime. Dynamic text is inserted exclusively
 * via ``document.createTextNode`` so report/evidence data can never inject
 * markup. Exports are generated in-page and handed to the browser as Blob
 * downloads.
 *
 * Workload labels are always visible text; the pinned Microsoft product marks
 * (``window.LICENSELENS_WORKLOAD_ICONS`` -> hashed offline assets under
 * ``assets/``) render as decorative ``<img>`` next to those labels.
 *
 * DESIGN_V2 responsibilities beyond the server-rendered shell:
 *   - the signature opening choreography (identity -> meta -> posture
 *     count-up 0..N -> radial draw + distribution fill -> implication ->
 *     top actions), 500-1000ms total, data-driven at every stage, opt-in via
 *     ``body.revealed``; reduced motion renders the instant final state;
 *   - the interactive capability constellation: nodes resolve from neutral
 *     column by column, group captions cross-filter by workload, workload
 *     selection reconfigures group order via FLIP;
 *   - capability selection filters section D by related check ids;
 *   - finding focus elevates the selected finding and highlights its related
 *     node and chart bars; chart bars are cross-filter buttons;
 *   - deep links (#finding-<id>, #section-a..e), filter state synced to the
 *     URL hash, sticky-nav scrollspy with ``aria-current``.
 */
(function () {
  "use strict";

  var report = window.LICENSELENS_REPORT_JSON || {};
  var vm = window.LICENSELENS_VIEWMODEL || {};
  var workloadIcons = window.LICENSELENS_WORKLOAD_ICONS || {};

  var REDUCED_MOTION = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);

  var PRESENTATION = {
    gap: "Action required",
    partial: "Incomplete",
    ok: "Operational",
    not_licensed: "Not licensed",
    skipped: "Not assessed",
    error: "Verification failed"
  };
  var SEVERITY_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
  var CONFIDENCE_LABEL = { high: "High", medium: "Medium", low: "Low" };
  var SCOPE_LABEL = { admin: "Administrator scope", all_users: "All users", devices: "All devices", data: "Tenant data" };
  var MODE_LABEL = {
    direct: "Read directly",
    proxy: "Approximated — verify in portal",
    manual: "Manual review",
    direct_with_proxy_fallback: "Read directly (with fallback)",
    unsupported: "Unsupported"
  };
  var EFFORT_LABEL = { minutes: "~minutes", hours: "~a few hours", half_day: "~half a day", days: "~days" };
  var WORKLOAD_LABEL = {
    identity: "Identity", endpoint: "Endpoint", defender: "Defender", sentinel: "Sentinel",
    purview: "Purview", exchange: "Exchange", collaboration: "Collaboration", teams: "Teams",
    power_platform: "Power Platform", power_bi: "Power BI", intune: "Intune", azure: "Azure",
    general: "General"
  };
  var WORKLOAD_ORDER = [
    "identity", "endpoint", "defender", "sentinel", "purview", "exchange",
    "collaboration", "teams", "power_platform", "power_bi", "intune", "azure", "general"
  ];
  var STATUS_ORDER = ["gap", "partial", "ok", "not_licensed", "skipped", "error"];
  var SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
  var CONFIDENCE_ORDER = ["high", "medium", "low"];
  var MODE_ORDER = ["direct", "proxy", "manual", "direct_with_proxy_fallback", "unsupported"];
  // Effort sort ranks least effort first (most actionable); deterministic.
  var EFFORT_ORDER = ["minutes", "hours", "half_day", "days"];

  var SVG_NS = "http:\/\/www.w3.org\/2000\/svg";
  var SVG_OPEN = '<svg class="status-glyph" viewBox="0 0 24 24" width="14" height="14" aria-hidden="true" focusable="false">';
  var GLYPHS = {
    gap: SVG_OPEN + '<path fill="currentColor" d="M4 4h7v3H7v10h4v3H4V4zm9 0 7 8-7 8v-5h-4v-6h4V4z"/></svg>',
    partial: SVG_OPEN + '<path fill="currentColor" d="M4 4h16v16H4V4zm3 3v10h5V7H7z"/>' +
      '<path fill="none" stroke="currentColor" stroke-width="2" d="M4 4h16v16H4z"/></svg>',
    ok: SVG_OPEN + '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/>' +
      '<path fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" d="M7.5 12.5 10.5 15.5 16.5 9"/></svg>',
    not_licensed: SVG_OPEN + '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/>' +
      '<path fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" d="M8 8l8 8"/></svg>',
    skipped: SVG_OPEN + '<path fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" d="M6 12h12"/></svg>',
    error: SVG_OPEN + '<path fill="currentColor" d="M12 3 22 20H2L12 3zm0 5.5c-.7 0-1.2.6-1.1 1.3l.5 5.2h1.2l.5-5.2c.1-.7-.4-1.3-1.1-1.3zM12 18.2a1.1 1.1 0 1 0 0-2.2 1.1 1.1 0 0 0 0 2.2z"/></svg>'
  };

  var GROUPS = [
    { key: "status", label: "Status", values: STATUS_ORDER, labels: PRESENTATION, dynamic: false, glyph: true },
    { key: "severity", label: "Severity", values: SEVERITY_ORDER, labels: SEVERITY_LABEL, dynamic: false },
    { key: "confidence", label: "Confidence", values: CONFIDENCE_ORDER, labels: CONFIDENCE_LABEL, dynamic: false },
    { key: "mode", label: "Mode", values: MODE_ORDER, labels: MODE_LABEL, dynamic: false },
    { key: "pack", label: "Pack", values: [], labels: {}, dynamic: true },
    { key: "workload", label: "Workload", values: [], labels: WORKLOAD_LABEL, dynamic: true }
  ];

  var CSV_COLUMNS = [
    ["check_id", "Check ID"], ["title", "Title"], ["status", "Status"],
    ["severity", "Severity"], ["confidence", "Confidence"], ["evaluation_mode", "Evaluation mode"],
    ["workload", "Workload"], ["effort", "Effort"], ["blast_radius", "Scope"],
    ["pack", "Pack"], ["summary", "Summary"], ["remediation", "Remediation"],
    ["customer_next_step", "Next step"], ["data_sources", "Data sources"],
    ["limitations", "Limitations"], ["entitlements_used", "Entitlements"], ["deep_link", "Admin page"]
  ];

  function el(tag, className) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    return node;
  }

  function svgEl(tag, attrs) {
    var node = document.createElementNS(SVG_NS, tag);
    for (var key in attrs) node.setAttribute(key, attrs[key]);
    return node;
  }

  function text(value) {
    return document.createTextNode(value == null ? "" : String(value));
  }

  function firstStr() {
    for (var i = 0; i < arguments.length; i++) {
      var v = arguments[i];
      if (v) return String(v);
    }
    return "";
  }

  function cap(value) {
    if (!value) return "";
    return String(value).charAt(0).toUpperCase() + String(value).slice(1);
  }

  function statusMarker(status, label) {
    var marker = el("span", "status-marker " + status);
    var holder = document.createElement("span");
    holder.innerHTML = GLYPHS[status] || GLYPHS.error;
    marker.appendChild(holder.firstChild);
    marker.appendChild(text(label));
    return marker;
  }

  function statusGlyph(status) {
    var holder = document.createElement("span");
    holder.innerHTML = GLYPHS[status] || GLYPHS.error;
    return holder.firstChild;
  }

  function workloadIconEl(workload, size) {
    var src = workloadIcons[workload];
    if (!src) return null;
    var img = document.createElement("img");
    img.className = "workload-icon";
    img.src = src;
    img.alt = "";
    img.width = size || 16;
    img.height = size || 16;
    img.setAttribute("decoding", "async");
    img.setAttribute("aria-hidden", "true");
    return img;
  }

  // Findings source: prefer the view-model E-section findings (pre-serialized
  // strings). The view-model omits a few export-relevant fields; re-attach them
  // from the full report payload by check_id so exports stay complete.
  var vmFindings = (vm.sections && vm.sections.E && Array.isArray(vm.sections.E.findings))
    ? vm.sections.E.findings
    : [];
  var rawFindings = Array.isArray(report.findings) ? report.findings : [];
  var findings = vmFindings.length ? vmFindings : rawFindings;
  if (vmFindings.length) {
    var rawByCheckId = {};
    rawFindings.forEach(function (f) { if (f && f.check_id) rawByCheckId[f.check_id] = f; });
    findings = vmFindings.map(function (f) {
      var raw = rawByCheckId[f.check_id];
      if (!raw) return f;
      var out = {};
      for (var key in f) out[key] = f[key];
      ["entitlements_used", "source_references", "accepted_risks", "references", "customer_title", "impact"]
        .forEach(function (key) { if (raw[key] !== undefined) out[key] = raw[key]; });
      return out;
    });
  }

  function findingById(checkId) {
    for (var i = 0; i < findings.length; i++) {
      if (findings[i].check_id === checkId) return findings[i];
    }
    return null;
  }

  function searchableText(f) {
    var parts = [
      f.check_id, f.title, f.customer_title, f.customer_summary, f.customer_next_step,
      f.summary, f.status, f.severity, f.confidence, f.workload, f.evaluation_mode,
      f.pack, f.status_label, f.confidence_label, f.deep_link, f.remediation
    ].concat(f.data_sources || [], f.limitations || [], f.entitlements_used || []);
    return parts.filter(Boolean).join(" ").toLowerCase();
  }

  function facetValue(f, key) {
    if (key === "mode") return String(f.evaluation_mode || "direct");
    return String(f[key] == null ? "" : f[key]);
  }

  var facets = findings.map(function (f) {
    return {
      text: searchableText(f),
      status: String(f.status || ""),
      severity: String(f.severity || ""),
      confidence: String(f.confidence || ""),
      mode: String(f.evaluation_mode || "direct"),
      pack: String(f.pack || ""),
      workload: String(f.workload || "")
    };
  });

  var state = {
    search: "",
    filters: { status: {}, severity: {}, confidence: {}, mode: {}, pack: {}, workload: {} },
    page: 1,
    pageSize: 25,
    sort: "impact",
    sortEngaged: false,
    selectedFinding: null,
    selectedCapability: null
  };

  var appNav = document.querySelector("[data-app-nav]");
  var workloadNav = document.querySelector("[data-workload-nav]");
  var sectionNav = document.querySelector("[data-section-nav]");
  var filterBar = document.querySelector("[data-filter-bar]");
  var listEl = document.querySelector("[data-findings-list]");
  var emptyEl = document.querySelector("[data-empty-state]");
  var paginationEl = document.querySelector("[data-pagination]");
  var visibleEl = document.querySelector("[data-visible-count]");
  var totalEl = document.querySelector("[data-total-count]");
  var searchEl = document.querySelector("#finding-search");
  var sortEl = document.querySelector("#finding-sort");
  var chartsEl = document.querySelector("[data-charts]");
  var printListEl = document.querySelector("[data-print-list]");
  var constellationEl = document.querySelector("[data-constellation]");
  var capabilityListEl = document.querySelector("[data-capability-list]");
  var dFilterStatusEl = document.querySelector("[data-d-filter-status]");

  function dynamicValues(key) {
    var present = {};
    facets.forEach(function (f) { if (f[key]) present[f[key]] = true; });
    if (key === "workload") {
      return WORKLOAD_ORDER.filter(function (w) { return present[w]; });
    }
    return Object.keys(present).sort();
  }

  GROUPS.forEach(function (group) {
    if (group.dynamic) group.values = dynamicValues(group.key);
  });

  // -------------------------------------------------------------------------
  // Workload navigation — tabs stay in sync with the workload facet filter
  // (single source of truth in ``state``; aria-current marks the active tab).
  // -------------------------------------------------------------------------
  function buildNav() {
    if (!workloadNav) return;
    var workloads = dynamicValues("workload");
    workloads.forEach(function (w) {
      var tab = el("a", "workload-tab");
      tab.setAttribute("href", "#findings");
      tab.setAttribute("data-nav", w);
      var icon = workloadIconEl(w);
      if (icon) tab.appendChild(icon);
      tab.appendChild(text(WORKLOAD_LABEL[w] || cap(w)));
      tab.addEventListener("click", function (event) {
        event.preventDefault();
        state.filters.workload = {};
        state.filters.workload[w] = true;
        state.page = 1;
        refresh();
      });
      workloadNav.appendChild(tab);
    });
    var allTab = workloadNav.querySelector('[data-nav="all"]');
    if (allTab) {
      allTab.addEventListener("click", function (event) {
        event.preventDefault();
        state.filters.workload = {};
        state.page = 1;
        refresh();
      });
    }
  }

  // -------------------------------------------------------------------------
  // Filter bar — one role="group" per facet; OR within a group, AND across.
  // Status chips show the status glyph beside the word (never color-only).
  // -------------------------------------------------------------------------
  function buildFilters() {
    if (!filterBar) return;
    GROUPS.forEach(function (group) {
      if (!group.values.length) return;
      var wrap = el("div", "filter-group");
      wrap.setAttribute("data-filter-group", group.key);
      wrap.setAttribute("role", "group");
      wrap.setAttribute("aria-label", "Filter by " + group.label);
      var label = el("span", "filter-group__label");
      label.appendChild(text(group.label));
      wrap.appendChild(label);
      group.values.forEach(function (value) {
        var btn = el("button", "filter-chip");
        btn.type = "button";
        btn.setAttribute("data-filter-value", value);
        btn.setAttribute("aria-pressed", "false");
        if (group.glyph) btn.appendChild(statusGlyph(value));
        btn.appendChild(text(group.labels[value] || cap(value)));
        btn.addEventListener("click", function () {
          if (state.filters[group.key][value]) {
            delete state.filters[group.key][value];
          } else {
            state.filters[group.key][value] = true;
          }
          state.page = 1;
          refresh();
        });
        wrap.appendChild(btn);
      });
      filterBar.appendChild(wrap);
    });

    var clearBtn = el("button", "filter-clear");
    clearBtn.type = "button";
    clearBtn.setAttribute("data-clear-filters", "");
    clearBtn.appendChild(text("Clear all"));
    clearBtn.addEventListener("click", function () {
      state.search = "";
      GROUPS.forEach(function (g) { state.filters[g.key] = {}; });
      state.page = 1;
      if (searchEl) searchEl.value = "";
      refresh();
    });
    filterBar.appendChild(clearBtn);
  }

  function buildPagination() {
    if (!paginationEl) return;
    var prev = el("button", "pager");
    prev.type = "button";
    prev.setAttribute("data-pager", "prev");
    prev.setAttribute("aria-label", "Previous page");
    prev.appendChild(text("Prev"));
    prev.addEventListener("click", function () {
      state.page -= 1;
      refresh();
    });

    var indicator = el("span", "pagination__info");
    indicator.setAttribute("data-page-indicator", "");

    var next = el("button", "pager");
    next.type = "button";
    next.setAttribute("data-pager", "next");
    next.setAttribute("aria-label", "Next page");
    next.appendChild(text("Next"));
    next.addEventListener("click", function () {
      state.page += 1;
      refresh();
    });

    var sizeLabel = el("label", "pagination__size");
    var sizeText = el("span");
    sizeText.appendChild(text("Per page"));
    var size = el("select");
    size.setAttribute("data-page-size", "");
    size.setAttribute("aria-label", "Results per page");
    ["25", "50", "100"].forEach(function (value) {
      var opt = el("option");
      opt.value = value;
      opt.appendChild(text(value));
      if (value === "25") opt.selected = true;
      size.appendChild(opt);
    });
    size.addEventListener("change", function () {
      state.pageSize = parseInt(size.value, 10) || 25;
      state.page = 1;
      refresh();
    });
    sizeLabel.appendChild(sizeText);
    sizeLabel.appendChild(size);

    paginationEl.appendChild(prev);
    paginationEl.appendChild(indicator);
    paginationEl.appendChild(next);
    paginationEl.appendChild(sizeLabel);
  }

  function buildTools() {
    var exportJson = document.querySelector("[data-export='json']");
    var exportCsv = document.querySelector("[data-export='csv']");
    var printBtn = document.querySelector("[data-print]");
    if (exportJson) exportJson.addEventListener("click", exportJsonFn);
    if (exportCsv) exportCsv.addEventListener("click", exportCsvFn);
    if (printBtn) printBtn.addEventListener("click", function () { window.print(); });
    if (sortEl) {
      sortEl.addEventListener("change", function () {
        state.sort = sortEl.value;
        state.sortEngaged = true;
        state.page = 1;
        refresh();
      });
    }
  }

  function groupMatches(key, value) {
    var selected = Object.keys(state.filters[key]);
    if (!selected.length) return true;
    return selected.indexOf(value) !== -1;
  }

  function matches(entry) {
    if (state.search) {
      for (var i = 0; i < state.search.length; i++) {
        if (entry.text.indexOf(state.search[i]) === -1) return false;
      }
    }
    if (!groupMatches("status", entry.status)) return false;
    if (!groupMatches("severity", entry.severity)) return false;
    if (!groupMatches("confidence", entry.confidence)) return false;
    if (!groupMatches("mode", entry.mode)) return false;
    if (!groupMatches("pack", entry.pack)) return false;
    if (!groupMatches("workload", entry.workload)) return false;
    return true;
  }

  function filteredFindings() {
    var out = [];
    for (var i = 0; i < findings.length; i++) {
      if (matches(facets[i])) out.push(findings[i]);
    }
    return out;
  }

  // Sort control. The engine's findings order (status priority, then severity,
  // then check_id) is the canonical "Impact (default)" presentation: the
  // default state renders the view-model order byte-for-byte. The comparators
  // below only apply once the user engages the control; all are deterministic
  // and locale-insensitive. Array.prototype.sort is stable in modern engines,
  // so ties keep the engine order.
  function rankOf(order, value) {
    var idx = order.indexOf(value);
    return idx === -1 ? order.length : idx;
  }

  function compareByCheckId(a, b) {
    var ca = String(a.check_id || "");
    var cb = String(b.check_id || "");
    if (ca < cb) return -1;
    if (ca > cb) return 1;
    return 0;
  }

  function compareImpact(a, b) {
    var diff = rankOf(SEVERITY_ORDER, String(a.severity || "")) -
      rankOf(SEVERITY_ORDER, String(b.severity || ""));
    if (diff !== 0) return diff;
    diff = rankOf(STATUS_ORDER, String(a.status || "")) -
      rankOf(STATUS_ORDER, String(b.status || ""));
    if (diff !== 0) return diff;
    return compareByCheckId(a, b);
  }

  function compareSeverity(a, b) {
    var diff = rankOf(SEVERITY_ORDER, String(a.severity || "")) -
      rankOf(SEVERITY_ORDER, String(b.severity || ""));
    if (diff !== 0) return diff;
    diff = rankOf(STATUS_ORDER, String(a.status || "")) -
      rankOf(STATUS_ORDER, String(b.status || ""));
    if (diff !== 0) return diff;
    return compareByCheckId(a, b);
  }

  function compareEffort(a, b) {
    var diff = rankOf(EFFORT_ORDER, String(a.effort || "")) -
      rankOf(EFFORT_ORDER, String(b.effort || ""));
    if (diff !== 0) return diff;
    diff = rankOf(SEVERITY_ORDER, String(a.severity || "")) -
      rankOf(SEVERITY_ORDER, String(b.severity || ""));
    if (diff !== 0) return diff;
    return compareByCheckId(a, b);
  }

  function compareTitle(a, b) {
    var ta = String(a.title || "");
    var tb = String(b.title || "");
    if (ta < tb) return -1;
    if (ta > tb) return 1;
    return compareByCheckId(a, b);
  }

  function sortedFindings(list) {
    if (!state.sortEngaged) return list;
    var out = list.slice();
    var comparator = compareImpact;
    if (state.sort === "severity") comparator = compareSeverity;
    else if (state.sort === "effort") comparator = compareEffort;
    else if (state.sort === "title") comparator = compareTitle;
    out.sort(comparator);
    return out;
  }

  function metaItem(key, value) {
    var wrap = el("span", "meta-item");
    var keySpan = el("span", "meta-key");
    keySpan.appendChild(text(key + ":"));
    wrap.appendChild(keySpan);
    wrap.appendChild(text(" " + value));
    return wrap;
  }

  function kv(key, value) {
    var p = el("p");
    var strong = el("strong");
    strong.appendChild(text(key + ":"));
    p.appendChild(strong);
    p.appendChild(text(" " + value));
    return p;
  }

  function joined(values) {
    return values && values.length ? values.join("; ") : "";
  }

  function renderFinding(f, isPrint) {
    var status = f.status || "error";
    var title = firstStr(f.title, f.customer_title, f.check_id);
    var article = el("article", (isPrint ? "print-finding " : "finding-row ") + status);
    article.setAttribute("data-status", status);
    article.setAttribute("data-workload", f.workload || "general");
    if (f.check_id && !isPrint) {
      // The D-section article owns the canonical id="finding-<check_id>"
      // (shared partial); the E row keeps only the selection hook.
      article.setAttribute("data-finding", f.check_id);
    }

    var head = el("div", "finding-head");
    head.appendChild(statusMarker(status, PRESENTATION[status] || status));
    var h3 = el("h3");
    if (isPrint) {
      h3.appendChild(text(title));
    } else {
      // The finding title is a real button: keyboard-selectable, focusable,
      // keeps heading semantics (button inside h3).
      var titleBtn = el("button", "finding-row__title");
      titleBtn.type = "button";
      titleBtn.appendChild(text(title));
      titleBtn.addEventListener("click", function () { selectFinding(f.check_id); });
      h3.appendChild(titleBtn);
    }
    head.appendChild(h3);
    article.appendChild(head);

    var meta = el("div", "finding-meta");
    if (f.severity) meta.appendChild(metaItem("Severity", SEVERITY_LABEL[f.severity] || cap(f.severity)));
    if (f.confidence) meta.appendChild(metaItem("Confidence", CONFIDENCE_LABEL[f.confidence] || cap(f.confidence)));
    if (f.evaluation_mode) meta.appendChild(metaItem("Mode", MODE_LABEL[f.evaluation_mode] || cap(f.evaluation_mode)));
    if (f.effort) meta.appendChild(metaItem("Effort", EFFORT_LABEL[f.effort] || f.effort));
    if (f.blast_radius) meta.appendChild(metaItem("Scope", SCOPE_LABEL[f.blast_radius] || String(f.blast_radius).replace(/_/g, " ")));
    if (f.workload) meta.appendChild(metaItem("Workload", WORKLOAD_LABEL[f.workload] || cap(f.workload)));
    if (meta.childNodes.length) article.appendChild(meta);

    var summary = firstStr(f.customer_summary, f.summary);
    if (summary) {
      var summaryP = el("p");
      summaryP.appendChild(text(summary));
      article.appendChild(summaryP);
    }
    if (f.customer_next_step) {
      var actionP = el("p");
      var actionStrong = el("strong");
      actionStrong.appendChild(text("Action:"));
      actionP.appendChild(actionStrong);
      actionP.appendChild(text(" " + f.customer_next_step));
      article.appendChild(actionP);
    }

    var details = el("details", "tech");
    var summaryEl = el("summary");
    summaryEl.appendChild(text("Technical evidence"));
    details.appendChild(summaryEl);
    details.appendChild(kv("Confidence", f.confidence_label || "Not reported"));
    details.appendChild(kv("Data sources", joined(f.data_sources) || "Not reported"));
    details.appendChild(kv("Limitations", joined(f.limitations) || "None reported"));
    if (f.deep_link) {
      var linkP = el("p");
      var link = el("a");
      link.setAttribute("href", f.deep_link);
      link.appendChild(text("Open Microsoft admin page"));
      linkP.appendChild(link);
      details.appendChild(linkP);
    }
    details.appendChild(kv("Technical ID", f.check_id));
    article.appendChild(details);

    return article;
  }

  function renderList(slice) {
    listEl.textContent = "";
    var frag = document.createDocumentFragment();
    slice.forEach(function (f) { frag.appendChild(renderFinding(f, false)); });
    listEl.appendChild(frag);
  }

  function renderPrintList(filtered) {
    if (!printListEl) return;
    printListEl.textContent = "";
    var frag = document.createDocumentFragment();
    filtered.forEach(function (f) { frag.appendChild(renderFinding(f, true)); });
    printListEl.appendChild(frag);
  }

  // -------------------------------------------------------------------------
  // Charts: local inline SVG / HTML bars with a name, a textual description,
  // a visually-hidden equivalent table, and one cross-filter button per row.
  // The role="img" visual layer and the overlay buttons are siblings inside
  // the figure, so the buttons stay reachable in the accessibility tree while
  // the visual keeps its name/description contract.
  // -------------------------------------------------------------------------

  function countBy(key, order, presentOnly) {
    var counts = {};
    findings.forEach(function (f) {
      var v = String(f[key] == null ? "" : f[key]);
      counts[v] = (counts[v] || 0) + 1;
    });
    var keys = presentOnly ? order.filter(function (k) { return counts[k] > 0; }) : order.slice();
    return keys.map(function (k) {
      return { key: k, value: counts[k] || 0 };
    });
  }

  function chartItems() {
    return [
      { name: "Findings by status", key: "status", label: PRESENTATION, order: STATUS_ORDER, presentOnly: false },
      { name: "Findings by workload", key: "workload", label: WORKLOAD_LABEL, order: WORKLOAD_ORDER, presentOnly: true },
      { name: "Findings by confidence", key: "confidence", label: CONFIDENCE_LABEL, order: CONFIDENCE_ORDER, presentOnly: false },
      { name: "Findings by evaluation mode", key: "evaluation_mode", label: MODE_LABEL, order: MODE_ORDER, presentOnly: false }
    ];
  }

  function barClass(key, chartKey) {
    if (chartKey === "status") {
      return "chart-bar chart-bar--" + key;
    }
    if (chartKey === "confidence") {
      return "chart-bar chart-bar--confidence-" + key;
    }
    return "chart-bar";
  }

  // Coarse pointers get 44px chart rows (target sizes, DESIGN_V2 4); fine
  // pointers keep the compact 28px pitch.
  function chartRowHeight() {
    if (window.matchMedia && window.matchMedia("(pointer: coarse)").matches) return 44;
    return 28;
  }

  function buildBars(items, chartKey) {
    var max = 1;
    items.forEach(function (i) { if (i.value > max) max = i.value; });
    var rowH = chartRowHeight();
    var barX = 120;
    var barW = 210;
    var svg = svgEl("svg", {
      class: "chart-svg",
      viewBox: "0 0 360 " + (items.length * rowH + 4),
      "aria-hidden": "true",
      focusable: "false"
    });
    items.forEach(function (item, idx) {
      var y = idx * rowH + rowH - 8;
      var label = svgEl("text", { x: 6, y: y, class: "chart-label" });
      label.textContent = item.label;
      svg.appendChild(label);
      var w = item.value === 0 ? 0 : Math.max(2, Math.round(item.value / max * barW));
      var rect = svgEl("rect", {
        x: String(barX), y: String(y - rowH + 8), width: String(w), height: String(rowH - 12), rx: "2",
        class: barClass(item.key, chartKey)
      });
      svg.appendChild(rect);
      var valText = svgEl("text", { x: String(barX + w + 6), y: y, class: "chart-value" });
      valText.textContent = String(item.value);
      svg.appendChild(valText);
    });
    return svg;
  }

  function buildWorkloadRows(items) {
    var max = 1;
    items.forEach(function (i) { if (i.value > max) max = i.value; });
    var list = el("div", "chart-rows");
    items.forEach(function (item) {
      var row = el("div", "chart-row");
      var label = el("span", "chart-row__label");
      var icon = workloadIconEl(item.key);
      if (icon) label.appendChild(icon);
      label.appendChild(text(item.label));
      row.appendChild(label);
      var track = el("div", "chart-row__track");
      var bar = el("div", "chart-row__bar chart-bar");
      var pct = item.value === 0 ? 0 : Math.max(4, Math.round(item.value / max * 100));
      bar.style.width = pct + "%";
      track.appendChild(bar);
      row.appendChild(track);
      var val = el("span", "chart-row__value");
      val.appendChild(text(String(item.value)));
      row.appendChild(val);
      list.appendChild(row);
    });
    return list;
  }

  // One cross-filter button per bar row, positioned over the visual. The
  // accessible name mirrors the facet ("Filter findings: <label>"); activating
  // toggles the facet filter and scrolls section E's list into view.
  function buildChartHits(fig, items, chartKey, rows) {
    var hits = el("div", "chart-hits");
    items.forEach(function (item, idx) {
      var hit = el("button", "chart-hit");
      hit.type = "button";
      hit.setAttribute("aria-label", "Filter findings: " + item.label);
      hit.setAttribute("data-chart-hit", "");
      hit.setAttribute("data-chart-key", chartKey);
      hit.setAttribute("data-chart-value", item.key);
      hit.setAttribute("aria-pressed", "false");
      if (rows && rows[idx]) {
        hit.style.top = String(rows[idx].offsetTop) + "px";
        hit.style.height = String(rows[idx].offsetHeight) + "px";
      } else {
        var rowH = chartRowHeight();
        hit.style.top = String(idx * rowH) + "px";
        hit.style.height = String(rowH) + "px";
      }
      hit.addEventListener("click", function () {
        var wasActive = !!state.filters[chartKey][item.key];
        if (wasActive) delete state.filters[chartKey][item.key];
        else state.filters[chartKey][item.key] = true;
        state.page = 1;
        refresh();
        if (!wasActive && listEl) listEl.scrollIntoView();
      });
      hits.appendChild(hit);
    });
    return hits;
  }

  function chartTable(name, items) {
    var table = el("table", "sr-only");
    table.setAttribute("data-chart-table", "");
    var caption = el("caption");
    caption.appendChild(text(name));
    table.appendChild(caption);
    var thead = el("thead");
    var hr = el("tr");
    var thCategory = el("th");
    thCategory.appendChild(text("Category"));
    var thCount = el("th");
    thCount.appendChild(text("Count"));
    hr.appendChild(thCategory);
    hr.appendChild(thCount);
    thead.appendChild(hr);
    table.appendChild(thead);
    var tbody = el("tbody");
    items.forEach(function (item) {
      var tr = el("tr");
      var tdCategory = el("td");
      tdCategory.appendChild(text(item.label));
      var tdCount = el("td");
      tdCount.appendChild(text(String(item.value)));
      tr.appendChild(tdCategory);
      tr.appendChild(tdCount);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    return table;
  }

  function describeItems(name, items) {
    var parts = items.map(function (i) { return i.label + ": " + i.value; });
    return name + ". " + parts.join(", ") + ".";
  }

  function chartFigure(spec) {
    var items = countBy(spec.key, spec.order, spec.presentOnly).map(function (i) {
      return { key: i.key, label: spec.label[i.key] || cap(i.key), value: i.value };
    });
    var key = spec.key;
    var fig = el("figure", "chart");
    fig.setAttribute("data-chart", key);

    var titleId = "chart-" + key + "-title";
    var descId = "chart-" + key + "-desc";

    var caption = el("figcaption");
    caption.id = titleId;
    caption.appendChild(text(spec.name));
    fig.appendChild(caption);

    var body = el("div", "chart__body");
    var visual = el("div", "chart__visual");
    visual.setAttribute("role", "img");
    visual.setAttribute("aria-labelledby", titleId);
    visual.setAttribute("aria-describedby", descId);
    var rows = null;
    if (key === "workload") {
      rows = buildWorkloadRows(items);
      visual.appendChild(rows);
    } else {
      visual.appendChild(buildBars(items, key));
    }
    body.appendChild(visual);
    body.appendChild(buildChartHits(fig, items, key, key === "workload" ? rows.children : null));
    fig.appendChild(body);

    var desc = el("p", "sr-only");
    desc.id = descId;
    desc.appendChild(text(describeItems(spec.name, items)));
    fig.appendChild(desc);

    fig.appendChild(chartTable(spec.name, items));
    return fig;
  }

  function renderCharts() {
    if (!chartsEl) return;
    chartsEl.textContent = "";
    if (!findings.length) {
      var empty = el("p", "chart-empty");
      empty.setAttribute("data-chart-empty", "");
      empty.appendChild(text("No findings to chart."));
      chartsEl.appendChild(empty);
      return;
    }
    var frag = document.createDocumentFragment();
    chartItems().forEach(function (spec) { frag.appendChild(chartFigure(spec)); });
    chartsEl.appendChild(frag);
  }

  // -------------------------------------------------------------------------
  // Export (client-side Blob downloads) and print.
  // -------------------------------------------------------------------------

  function csvEscape(value) {
    var s = value == null ? "" : String(value);
    if (s !== "" && "\t\r\n=+-@".indexOf(s.charAt(0)) !== -1) {
      s = "'" + s;
    }
    if (/[",\r\n]/.test(s)) {
      s = '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
  }

  function csvCell(f, column) {
    var value = f[column[0]];
    if (Array.isArray(value)) value = value.join("; ");
    return csvEscape(value);
  }

  function buildCsv(filtered) {
    var rows = [CSV_COLUMNS.map(function (column) { return csvEscape(column[1]); })];
    filtered.forEach(function (f) {
      rows.push(CSV_COLUMNS.map(function (column) { return csvCell(f, column); }));
    });
    return rows.map(function (row) { return row.join(","); }).join("\r\n") + "\r\n";
  }

  function buildJson(filtered) {
    return JSON.stringify(filtered, null, 2);
  }

  function download(filename, mime, content) {
    var blob = new Blob([content], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.setAttribute("rel", "noopener");
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function exportJsonFn() {
    download("licenselens-findings.json", "application/json", buildJson(filteredFindings()));
  }

  function exportCsvFn() {
    download("licenselens-findings.csv", "text/csv", buildCsv(filteredFindings()));
  }

  function hasActiveFilters() {
    if (state.search) return true;
    return GROUPS.some(function (g) { return Object.keys(state.filters[g.key]).length > 0; });
  }

  // -------------------------------------------------------------------------
  // URL hash — filters sync to the hash (replaceState, never a scroll) and
  // restore on load. Values are enum keys, so the encoding is deterministic.
  // -------------------------------------------------------------------------

  function encodeFilters() {
    var parts = [];
    GROUPS.forEach(function (g) {
      var active = g.values.filter(function (v) { return !!state.filters[g.key][v]; });
      if (active.length) parts.push(g.key + "=" + active.join(","));
    });
    return parts.length ? "#filters=" + parts.join(";") : "";
  }

  function decodeFilters(hash) {
    var body = hash.slice("#filters=".length);
    body.split(";").forEach(function (pair) {
      if (!pair) return;
      var eq = pair.indexOf("=");
      if (eq === -1) return;
      var key = pair.slice(0, eq);
      var known = false;
      GROUPS.forEach(function (g) { if (g.key === key) known = true; });
      if (!known) return;
      pair.slice(eq + 1).split(",").forEach(function (v) {
        if (v) state.filters[key][v] = true;
      });
    });
  }

  function syncHash() {
    var encoded = encodeFilters();
    var current = window.location.hash || "";
    if (encoded && current !== encoded) {
      window.history.replaceState(null, "", encoded);
    } else if (!encoded && current.indexOf("#filters=") === 0) {
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
    }
  }

  // -------------------------------------------------------------------------
  // Selection — exactly one selected finding at a time; the selected finding
  // elevates and highlights its related constellation node and chart bars.
  // -------------------------------------------------------------------------

  function selectFinding(checkId) {
    state.selectedFinding = checkId;
    updateFindingSelection();
  }

  function updateFindingSelection() {
    var id = state.selectedFinding;
    var f = id ? findingById(id) : null;
    var caps = (f && Array.isArray(f.entitlements_used)) ? f.entitlements_used : [];
    var capSet = {};
    caps.forEach(function (c) { capSet[c] = true; });
    var rel = {};
    if (f) {
      rel.status = String(f.status || "");
      rel.workload = String(f.workload || "");
      rel.confidence = String(f.confidence || "");
      rel.evaluation_mode = String(f.evaluation_mode || "");
    }
    var rows = listEl ? listEl.querySelectorAll(".finding-row") : [];
    Array.prototype.forEach.call(rows, function (row) {
      row.classList.toggle("is-selected", row.getAttribute("data-finding") === id);
    });
    var wraps = document.querySelectorAll("[data-finding-wrap]");
    Array.prototype.forEach.call(wraps, function (wrap) {
      wrap.classList.toggle("is-selected", wrap.getAttribute("data-finding") === id);
    });
    if (constellationEl) {
      var points = constellationEl.querySelectorAll(".constellation-point");
      Array.prototype.forEach.call(points, function (point) {
        point.classList.toggle("is-related", !!capSet[point.getAttribute("data-capability-id")]);
      });
    }
    var hits = document.querySelectorAll("[data-chart-hit]");
    Array.prototype.forEach.call(hits, function (hit) {
      var chartKey = hit.getAttribute("data-chart-key");
      hit.classList.toggle("is-related", rel[chartKey] === hit.getAttribute("data-chart-value"));
    });
  }

  // -------------------------------------------------------------------------
  // Capability selection — filters section D to the capability's related
  // check ids and scrolls to section D. Exactly one capability selected.
  // -------------------------------------------------------------------------

  function capabilityCheckIds(capId) {
    var ids = [];
    rawFindings.forEach(function (f) {
      var used = f.entitlements_used || [];
      if (used.indexOf(capId) !== -1 && f.check_id) ids.push(f.check_id);
    });
    return ids;
  }

  function capabilityPlainName(capId) {
    var constellation = Array.isArray(vm.constellation) ? vm.constellation : [];
    for (var i = 0; i < constellation.length; i++) {
      if (constellation[i].id === capId) return constellation[i].plain_name || capId;
    }
    return capId;
  }

  function selectCapability(capId) {
    var next = state.selectedCapability === capId ? null : capId;
    state.selectedCapability = next;
    updateCapabilitySelection();
    if (next) {
      var sectionD = document.getElementById("section-d");
      if (sectionD) sectionD.scrollIntoView();
    }
  }

  function updateCapabilitySelection() {
    var capId = state.selectedCapability;
    if (capabilityListEl) {
      var selects = capabilityListEl.querySelectorAll("[data-capability-select]");
      Array.prototype.forEach.call(selects, function (btn) {
        var active = btn.getAttribute("data-capability-select") === capId;
        btn.setAttribute("aria-pressed", active ? "true" : "false");
        var row = btn.closest(".capability-row");
        if (row) row.classList.toggle("is-selected", active);
      });
    }
    if (constellationEl) {
      var points = constellationEl.querySelectorAll(".constellation-point");
      Array.prototype.forEach.call(points, function (point) {
        var active = point.getAttribute("data-capability-id") === capId;
        point.setAttribute("aria-pressed", active ? "true" : "false");
        point.classList.toggle("is-selected", active);
      });
    }
    applyCapabilityFilter();
  }

  function applyCapabilityFilter() {
    var wraps = document.querySelectorAll("[data-finding-wrap]");
    if (!wraps.length) return;
    var capId = state.selectedCapability;
    if (!capId) {
      Array.prototype.forEach.call(wraps, function (w) { w.hidden = false; });
      renderDFilterStatus();
      return;
    }
    var ids = capabilityCheckIds(capId);
    var idSet = {};
    ids.forEach(function (id) { idSet[id] = true; });
    var shown = 0;
    Array.prototype.forEach.call(wraps, function (w) {
      var show = !!idSet[w.getAttribute("data-finding")];
      w.hidden = !show;
      if (show) shown++;
    });
    renderDFilterStatus(shown, ids.length, capId);
  }

  function renderDFilterStatus(shown, related, capId) {
    if (!dFilterStatusEl) return;
    dFilterStatusEl.textContent = "";
    if (!capId) return;
    var span = el("span");
    span.appendChild(text("Showing " + shown + " of " + related + " findings related to " + capabilityPlainName(capId) + "."));
    dFilterStatusEl.appendChild(span);
    var clearBtn = el("button");
    clearBtn.type = "button";
    clearBtn.appendChild(text("Clear capability filter"));
    clearBtn.addEventListener("click", function () { selectCapability(capId); });
    dFilterStatusEl.appendChild(clearBtn);
  }

  // -------------------------------------------------------------------------
  // Constellation — the shared macro already renders group captions and
  // nodes as real buttons. This layer wires them: captions toggle the
  // workload facet filter (cross-filtering), nodes select the capability
  // (filtering section D by its related check ids). Workload selection
  // reconfigures the group order via FLIP; the neutral-to-status resolve
  // animation comes from the shared foundation (body.revealed).
  // -------------------------------------------------------------------------

  function wireConstellation() {
    if (!constellationEl) return;
    var captions = constellationEl.querySelectorAll("button.constellation-caption");
    Array.prototype.forEach.call(captions, function (caption) {
      var wl = caption.getAttribute("data-workload") || "general";
      caption.addEventListener("click", function () {
        if (state.filters.workload[wl]) delete state.filters.workload[wl];
        else state.filters.workload[wl] = true;
        state.page = 1;
        refresh();
      });
    });
    var points = constellationEl.querySelectorAll("button.constellation-point");
    Array.prototype.forEach.call(points, function (point) {
      point.addEventListener("click", function () {
        var capId = point.getAttribute("data-capability-id");
        if (capId) selectCapability(capId);
      });
    });
  }

  function workloadRank(workload) {
    var idx = WORKLOAD_ORDER.indexOf(workload);
    return idx === -1 ? WORKLOAD_ORDER.length : idx;
  }

  function reorderConstellation(animate) {
    if (!constellationEl) return;
    var groups = Array.prototype.slice.call(constellationEl.querySelectorAll(".constellation-group"));
    if (groups.length < 2) return;
    var legend = constellationEl.querySelector(".constellation-legend");

    groups.forEach(function (group) {
      var wl = group.getAttribute("data-workload") || "general";
      group.classList.toggle("is-selected", !!state.filters.workload[wl]);
    });

    var target = groups.slice().sort(function (a, b) {
      var sa = state.filters.workload[a.getAttribute("data-workload")] ? 0 : 1;
      var sb = state.filters.workload[b.getAttribute("data-workload")] ? 0 : 1;
      if (sa !== sb) return sa - sb;
      return workloadRank(a.getAttribute("data-workload")) - workloadRank(b.getAttribute("data-workload"));
    });

    var sameOrder = groups.every(function (group, idx) { return group === target[idx]; });
    if (sameOrder) return;

    if (!animate || REDUCED_MOTION) {
      target.forEach(function (group) {
        constellationEl.insertBefore(group, legend);
      });
      return;
    }

    // FLIP: First — measure. Last — reorder the DOM (the only thing that
    // changes). Invert — translate by the delta. Play — settle to identity.
    var firstRects = groups.map(function (group) { return group.getBoundingClientRect(); });
    target.forEach(function (group) {
      constellationEl.insertBefore(group, legend);
    });
    groups.forEach(function (group, idx) {
      var rect = group.getBoundingClientRect();
      var dx = firstRects[idx].left - rect.left;
      var dy = firstRects[idx].top - rect.top;
      if (dx || dy) {
        group.style.transform = "translate(" + dx + "px, " + dy + "px)";
      }
    });
    void constellationEl.offsetWidth;
    groups.forEach(function (group) {
      group.style.transition = "transform 300ms ease-out";
      group.style.transform = "";
    });
    window.setTimeout(function () {
      groups.forEach(function (group) {
        group.style.transition = "";
        group.style.transform = "";
      });
    }, 320);
  }

  // -------------------------------------------------------------------------
  // Refresh — filter, sort, page, render, then sync every control surface.
  // -------------------------------------------------------------------------

  function updateButtons() {
    var chips = filterBar ? filterBar.querySelectorAll("[data-filter-value]") : [];
    Array.prototype.forEach.call(chips, function (btn) {
      var groupKey = btn.parentNode.getAttribute("data-filter-group");
      var value = btn.getAttribute("data-filter-value");
      var active = !!(groupKey && state.filters[groupKey] && state.filters[groupKey][value]);
      btn.setAttribute("aria-pressed", active ? "true" : "false");
      btn.classList.toggle("is-active", active);
    });
    var captions = constellationEl ? constellationEl.querySelectorAll("button.constellation-caption") : [];
    Array.prototype.forEach.call(captions, function (btn) {
      var wl = btn.getAttribute("data-workload");
      var active = !!state.filters.workload[wl];
      btn.setAttribute("aria-pressed", active ? "true" : "false");
    });
    var hits = document.querySelectorAll("[data-chart-hit]");
    Array.prototype.forEach.call(hits, function (hit) {
      var chartKey = hit.getAttribute("data-chart-key");
      var value = hit.getAttribute("data-chart-value");
      var active = !!(chartKey && state.filters[chartKey] && state.filters[chartKey][value]);
      hit.setAttribute("aria-pressed", active ? "true" : "false");
    });
    var clearBtn = filterBar ? filterBar.querySelector("[data-clear-filters]") : null;
    if (clearBtn) clearBtn.disabled = !hasActiveFilters();
  }

  function updateNav() {
    if (!workloadNav) return;
    var wl = Object.keys(state.filters.workload);
    var current = wl.length === 0 ? "all" : (wl.length === 1 ? wl[0] : null);
    Array.prototype.forEach.call(workloadNav.querySelectorAll("[data-nav]"), function (tab) {
      var active = current !== null && tab.getAttribute("data-nav") === current;
      tab.classList.toggle("is-active", active);
      if (active) tab.setAttribute("aria-current", "page");
      else tab.removeAttribute("aria-current");
    });
  }

  function refresh() {
    var filtered = sortedFindings(filteredFindings());
    var total = filtered.length;
    var pages = Math.max(1, Math.ceil(total / state.pageSize));
    if (state.page > pages) state.page = pages;
    if (state.page < 1) state.page = 1;

    var start = (state.page - 1) * state.pageSize;
    renderList(filtered.slice(start, start + state.pageSize));
    renderPrintList(filtered);

    if (visibleEl) visibleEl.textContent = String(total);
    if (totalEl) totalEl.textContent = String(findings.length);

    if (emptyEl) {
      emptyEl.hidden = total !== 0;
      emptyEl.textContent = findings.length === 0
        ? "No findings were produced by this scan."
        : "No findings match the current search and filters.";
    }

    if (paginationEl) {
      paginationEl.hidden = total === 0;
      var indicator = paginationEl.querySelector("[data-page-indicator]");
      var prev = paginationEl.querySelector('[data-pager="prev"]');
      var next = paginationEl.querySelector('[data-pager="next"]');
      if (indicator) indicator.textContent = "Page " + state.page + " of " + pages;
      if (prev) prev.disabled = state.page <= 1;
      if (next) next.disabled = state.page >= pages;
    }

    updateButtons();
    updateNav();
    reorderConstellation(true);
    updateFindingSelection();
    syncHash();
  }

  function onSearch() {
    state.search = searchEl ? String(searchEl.value).trim().toLowerCase().split(/\s+/).filter(Boolean) : [];
    state.page = 1;
    refresh();
  }

  // -------------------------------------------------------------------------
  // Signature opening choreography (DESIGN_V2 11). The server-rendered DOM is
  // the final state; app.js only opts the staged reveal in via body.revealed.
  // Reduced motion never gains the class and never animates: instant final
  // state with zero information loss.
  // -------------------------------------------------------------------------

  function posturePercent() {
    var figure = document.querySelector(".posture-figure");
    if (figure && figure.hasAttribute("data-realized")) {
      var fromAttr = parseInt(figure.getAttribute("data-realized"), 10);
      if (!isNaN(fromAttr)) return fromAttr;
    }
    var posture = (vm.sections && vm.sections.A && vm.sections.A.posture) || null;
    if (posture && typeof posture.realized_percent === "number") {
      return posture.realized_percent;
    }
    var rollup = report && report.capability_rollup;
    if (rollup && typeof rollup.realized_percent === "number") {
      return rollup.realized_percent;
    }
    return null;
  }

  function setPostureValue(value) {
    var digits = document.querySelector(".posture-figure .posture-digits");
    if (digits) digits.textContent = String(value);
  }

  // Stage 3: posture metric counts 0 -> N, rAF, 700ms ease-out, delay 120ms,
  // tabular numerals, lands exactly on N.
  function animatePostureCountUp(target) {
    var digits = document.querySelector(".posture-figure .posture-digits");
    if (!digits) return;
    var duration = 700;
    var started = null;
    function step(timestamp) {
      if (started === null) started = timestamp;
      var t = Math.min((timestamp - started) / duration, 1);
      var eased = 1 - Math.pow(1 - t, 3);
      digits.textContent = String(t >= 1 ? target : Math.round(eased * target));
      if (t < 1) window.requestAnimationFrame(step);
    }
    window.setTimeout(function () {
      window.requestAnimationFrame(step);
    }, 120);
  }

  // Stage 4a: the radial realization gauge draws via stroke-dashoffset,
  // 700ms ease-out, delay 160ms. The server-rendered offset is the final
  // state; the draw starts from the full circumference.
  function animatePostureGauge() {
    var arc = document.querySelector("[data-gauge-arc]");
    if (!arc) return;
    var r = parseFloat(arc.getAttribute("r"));
    if (isNaN(r) || r <= 0) return;
    var percent = posturePercent();
    if (percent === null) return;
    var circumference = 2 * Math.PI * r;
    var clamped = Math.min(Math.max(percent, 0), 100);
    var target = circumference * (1 - clamped / 100);
    arc.setAttribute("stroke-dasharray", String(circumference));
    arc.setAttribute("stroke-dashoffset", String(circumference));
    void arc.getBoundingClientRect();
    arc.style.transition = "stroke-dashoffset 700ms ease-out 160ms";
    arc.setAttribute("stroke-dashoffset", String(target));
  }

  // -------------------------------------------------------------------------
  // Reveal triggers: below-fold sections (one-shot observer), sticky-nav
  // scrollspy (IntersectionObserver, no scroll listeners), floating nav.
  // -------------------------------------------------------------------------

  function initSectionReveals() {
    var sections = document.querySelectorAll("[data-reveal]");
    if (!sections.length) return;
    if (!("IntersectionObserver" in window) || REDUCED_MOTION) {
      Array.prototype.forEach.call(sections, function (section) {
        section.classList.add("is-revealed");
      });
      return;
    }
    Array.prototype.forEach.call(sections, function (section) {
      // A deep link may have revealed a section already; never re-hide it.
      if (!section.classList.contains("is-revealed")) {
        section.classList.add("is-pending-reveal");
      }
    });
    var observer = new IntersectionObserver(function (entries, obs) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        var section = entry.target;
        var index = parseInt(section.getAttribute("data-reveal-index") || "0", 10);
        section.style.transitionDelay = String(40 * index) + "ms";
        section.classList.remove("is-pending-reveal");
        section.classList.add("is-revealed");
        obs.unobserve(section);
      });
    }, { threshold: 0.12 });
    Array.prototype.forEach.call(sections, function (section) { observer.observe(section); });
  }

  // Reveal the section that owns an element immediately (used by deep links
  // so scrollIntoView lands on the final layout, not a pre-reveal transform).
  function revealSectionOf(element) {
    if (!element) return;
    var section = element.closest("section");
    if (section && section.classList.contains("is-pending-reveal")) {
      section.style.transitionDelay = "0ms";
      section.classList.remove("is-pending-reveal");
      section.classList.add("is-revealed");
    }
  }

  function initScrollSpy() {
    if (!sectionNav || !("IntersectionObserver" in window)) return;
    var links = sectionNav.querySelectorAll("[data-section-link]");
    var sections = [];
    Array.prototype.forEach.call(links, function (link) {
      var target = document.getElementById(link.getAttribute("href").slice(1));
      if (target) sections.push({ link: link, el: target });
    });
    if (!sections.length) return;
    var current = sectionNav.querySelector('[data-section-link][aria-current="true"]');
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        var next = null;
        sections.forEach(function (s) { if (s.el === entry.target) next = s.link; });
        if (!next || current === next) return;
        if (current) current.removeAttribute("aria-current");
        next.setAttribute("aria-current", "true");
        current = next;
      });
    }, { rootMargin: "-30% 0px -60% 0px", threshold: 0 });
    sections.forEach(function (s) { observer.observe(s.el); });
  }

  function initNavFloating() {
    if (!appNav || !("IntersectionObserver" in window)) return;
    var sentinel = document.querySelector("[data-nav-sentinel]");
    if (!sentinel) return;
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        appNav.classList.toggle("is-floating", !entry.isIntersecting);
      });
    }, { threshold: 0 });
    observer.observe(sentinel);
  }

  function reveal() {
    if (REDUCED_MOTION) {
      var percent = posturePercent();
      if (percent !== null) setPostureValue(percent);
      document.body.classList.add("instant");
      return;
    }
    document.body.classList.add("revealed");
    var target = posturePercent();
    if (target !== null) animatePostureCountUp(target);
    animatePostureGauge();
    initSectionReveals();
  }

  // -------------------------------------------------------------------------
  // Boot — build controls, render charts, restore the hash, reveal.
  // -------------------------------------------------------------------------

  buildNav();
  buildFilters();
  buildPagination();
  buildTools();
  renderCharts();
  wireConstellation();

  if (searchEl) searchEl.addEventListener("input", onSearch);

  var initialHash = window.location.hash || "";
  if (initialHash.indexOf("#filters=") === 0) {
    decodeFilters(initialHash);
  } else if (initialHash.indexOf("#finding-") === 0) {
    var checkId = initialHash.slice("#finding-".length);
    GROUPS.forEach(function (g) { state.filters[g.key] = {}; });
    if (searchEl) searchEl.value = "";
    selectFinding(checkId);
    var index = -1;
    for (var i = 0; i < findings.length; i++) {
      if (findings[i].check_id === checkId) { index = i; break; }
    }
    if (index !== -1) state.page = Math.floor(index / state.pageSize) + 1;
  }

  refresh();

  if (initialHash.indexOf("#finding-") === 0) {
    var target = document.getElementById(initialHash.slice(1));
    if (target) {
      revealSectionOf(target);
      target.scrollIntoView();
    }
  }

  initScrollSpy();
  initNavFloating();

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", reveal);
  } else {
    reveal();
  }
})();
