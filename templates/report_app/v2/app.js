/* Versioned offline report application (report app v2).
 *
 * Everything is rendered client-side from the escaped data assets
 * ``window.LICENSELENS_REPORT_JSON`` and ``window.LICENSELENS_VIEWMODEL``.
 * No ``fetch``, no ``eval``, no inline event handlers, no third-party
 * runtime. Dynamic text is inserted exclusively via
 * ``document.createTextNode`` so report/evidence data can never inject markup.
 * Exports are generated in-page and handed to the browser as Blob downloads.
 * v2 is text-only: the retired v1 ``<img>`` workload-icon allowlist is gone,
 * workloads are named with visible text labels.
 */
(function () {
  "use strict";

  var report = window.LICENSELENS_REPORT_JSON || {};
  var vm = window.LICENSELENS_VIEWMODEL || {};

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
  var MODE_LABEL = { direct: "Direct", proxy: "Proxy", manual: "Manual", unsupported: "Unsupported" };
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
  var MODE_ORDER = ["direct", "proxy", "manual", "unsupported"];

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
    { key: "status", label: "Status", values: STATUS_ORDER, labels: PRESENTATION, dynamic: false },
    { key: "severity", label: "Severity", values: SEVERITY_ORDER, labels: SEVERITY_LABEL, dynamic: false },
    { key: "confidence", label: "Confidence", values: CONFIDENCE_ORDER, labels: CONFIDENCE_LABEL, dynamic: false },
    { key: "mode", label: "Mode", values: MODE_ORDER, labels: MODE_LABEL, dynamic: false },
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

  function searchableText(f) {
    var parts = [
      f.check_id, f.title, f.customer_title, f.customer_summary, f.customer_next_step,
      f.summary, f.status, f.severity, f.confidence, f.workload, f.evaluation_mode,
      f.status_label, f.confidence_label, f.deep_link, f.remediation
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
      workload: String(f.workload || "")
    };
  });

  var state = {
    search: "",
    filters: { status: {}, severity: {}, confidence: {}, mode: {}, workload: {} },
    page: 1,
    pageSize: 25,
    sort: "impact",
    sortEngaged: false
  };

  var nav = document.querySelector("[data-workload-nav]");
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

  function dynamicValues(key) {
    var present = {};
    facets.forEach(function (f) { if (f.workload) present[f.workload] = true; });
    return WORKLOAD_ORDER.filter(function (w) { return present[w]; });
  }

  GROUPS.forEach(function (group) {
    if (group.dynamic) group.values = dynamicValues(group.key);
  });

  function buildNav() {
    if (!nav) return;
    var workloads = dynamicValues("workload");
    workloads.forEach(function (w) {
      var tab = el("a", "workload-tab");
      tab.setAttribute("href", "#findings");
      tab.setAttribute("data-nav", w);
      tab.appendChild(text(WORKLOAD_LABEL[w] || cap(w)));
      tab.addEventListener("click", function (event) {
        event.preventDefault();
        state.filters.workload = {};
        state.filters.workload[w] = true;
        state.page = 1;
        refresh();
      });
      nav.appendChild(tab);
    });
    var allTab = nav.querySelector('[data-nav="all"]');
    if (allTab) {
      allTab.addEventListener("click", function (event) {
        event.preventDefault();
        state.filters.workload = {};
        state.page = 1;
        refresh();
      });
    }
  }

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
        state.sort = sortEl.value === "check_id" ? "check_id" : "impact";
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
  // then check_id) is the canonical "Impact (default)" presentation, so the
  // default state renders the view-model order byte-for-byte. The impact
  // comparator re-ranks by severity first, then status, then check_id and is
  // only applied once the user engages the control. Array.prototype.sort is
  // stable in modern engines, so ties keep the engine order.
  function rankOf(order, value) {
    var idx = order.indexOf(value);
    return idx === -1 ? order.length : idx;
  }

  function compareImpact(a, b) {
    var sev = rankOf(SEVERITY_ORDER, String(a.severity || "")) -
      rankOf(SEVERITY_ORDER, String(b.severity || ""));
    if (sev !== 0) return sev;
    var st = rankOf(STATUS_ORDER, String(a.status || "")) -
      rankOf(STATUS_ORDER, String(b.status || ""));
    if (st !== 0) return st;
    var ca = String(a.check_id || "");
    var cb = String(b.check_id || "");
    if (ca < cb) return -1;
    if (ca > cb) return 1;
    return 0;
  }

  function compareCheckId(a, b) {
    var ca = String(a.check_id || "");
    var cb = String(b.check_id || "");
    if (ca < cb) return -1;
    if (ca > cb) return 1;
    return 0;
  }

  function sortedFindings(list) {
    if (!state.sortEngaged) return list;
    var out = list.slice();
    out.sort(state.sort === "check_id" ? compareCheckId : compareImpact);
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
    if (f.check_id && !isPrint) article.id = "finding-" + f.check_id;

    var head = el("div", "finding-head");
    head.appendChild(statusMarker(status, PRESENTATION[status] || status));
    var h3 = el("h3");
    h3.appendChild(text(title));
    head.appendChild(h3);
    article.appendChild(head);

    var meta = el("div", "finding-meta");
    if (f.severity) meta.appendChild(metaItem("Severity", SEVERITY_LABEL[f.severity] || cap(f.severity)));
    if (f.confidence) meta.appendChild(metaItem("Confidence", CONFIDENCE_LABEL[f.confidence] || cap(f.confidence)));
    if (f.evaluation_mode) meta.appendChild(metaItem("Mode", MODE_LABEL[f.evaluation_mode] || cap(f.evaluation_mode)));
    if (f.effort) meta.appendChild(metaItem("Effort", EFFORT_LABEL[f.effort] || f.effort));
    if (f.blast_radius) meta.appendChild(metaItem("Scope", String(f.blast_radius).replace(/_/g, " ")));
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
  // Charts: local inline SVG bars with a name, a textual description, and a
  // visually-hidden equivalent table for nonvisual consumers.
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

  function buildBars(items, chartKey) {
    var max = 1;
    items.forEach(function (i) { if (i.value > max) max = i.value; });
    var rowH = 28;
    var barX = 120;
    var barW = 210;
    var svg = svgEl("svg", {
      class: "chart-svg",
      viewBox: "0 0 360 " + (items.length * rowH + 4),
      "aria-hidden": "true",
      focusable: "false"
    });
    items.forEach(function (item, idx) {
      var y = idx * rowH + 20;
      var label = svgEl("text", { x: 6, y: y, class: "chart-label" });
      label.textContent = item.label;
      svg.appendChild(label);
      var w = item.value === 0 ? 0 : Math.max(2, Math.round(item.value / max * barW));
      var rect = svgEl("rect", {
        x: String(barX), y: String(y - 13), width: String(w), height: "16", rx: "2",
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
    body.setAttribute("role", "img");
    body.setAttribute("aria-labelledby", titleId);
    body.setAttribute("aria-describedby", descId);
    if (key === "workload") {
      body.appendChild(buildWorkloadRows(items));
    } else {
      body.appendChild(buildBars(items, key));
    }
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

  function updateButtons() {
    var chips = filterBar ? filterBar.querySelectorAll("[data-filter-value]") : [];
    Array.prototype.forEach.call(chips, function (btn) {
      var groupKey = btn.parentNode.getAttribute("data-filter-group");
      var value = btn.getAttribute("data-filter-value");
      var active = !!(groupKey && state.filters[groupKey] && state.filters[groupKey][value]);
      btn.setAttribute("aria-pressed", active ? "true" : "false");
      btn.classList.toggle("is-active", active);
    });
    var clearBtn = filterBar ? filterBar.querySelector("[data-clear-filters]") : null;
    if (clearBtn) clearBtn.disabled = !hasActiveFilters();
  }

  function updateNav() {
    if (!nav) return;
    var wl = Object.keys(state.filters.workload);
    var current = wl.length === 0 ? "all" : (wl.length === 1 ? wl[0] : null);
    Array.prototype.forEach.call(nav.querySelectorAll("[data-nav]"), function (tab) {
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
  }

  function onSearch() {
    state.search = searchEl ? String(searchEl.value).trim().toLowerCase().split(/\s+/).filter(Boolean) : [];
    state.page = 1;
    refresh();
  }

  // Reveal trigger. Content is fully server-rendered; marking the body opts the
  // staggered "coming into focus" reveal in. Reduced motion skips it and jumps
  // straight to the final data values (instant-state contract).
  function posturePercent() {
    var posture = (vm.sections && vm.sections.A && vm.sections.A.posture) || null;
    if (posture && typeof posture.realized_percent === "number") {
      return posture.realized_percent;
    }
    var rollup = (report && report.capability_rollup) || null;
    if (rollup && typeof rollup.realized_percent === "number") {
      return rollup.realized_percent;
    }
    return null;
  }

  function setPostureValue(value) {
    var digits = document.querySelector(".posture-figure .posture-digits");
    if (digits) digits.textContent = String(value);
  }

  function animatePostureCountUp(target) {
    var digits = document.querySelector(".posture-figure .posture-digits");
    if (!digits) return;
    var duration = 700; // within the DESIGN_V2 500-1000ms motion window
    var start = null;
    function step(timestamp) {
      if (start === null) start = timestamp;
      var progress = Math.min((timestamp - start) / duration, 1);
      if (progress < 1) {
        digits.textContent = String(Math.round(progress * target));
        window.requestAnimationFrame(step);
      } else {
        digits.textContent = String(target);
      }
    }
    window.requestAnimationFrame(step);
  }

  function reveal() {
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      var percent = posturePercent();
      if (percent !== null) setPostureValue(percent);
      return;
    }
    document.body.classList.add('revealed');
    document.body.classList.add('constellation-settled');
    var target = posturePercent();
    if (target !== null) animatePostureCountUp(target);
  }

  buildNav();
  buildFilters();
  buildPagination();
  buildTools();
  renderCharts();

  if (searchEl) searchEl.addEventListener("input", onSearch);

  var initialHash = window.location.hash || "";
  if (initialHash.indexOf("#finding-") === 0) {
    var checkId = initialHash.slice("#finding-".length);
    for (var i = 0; i < findings.length; i++) {
      if (findings[i].check_id === checkId) {
        state.page = Math.floor(i / state.pageSize) + 1;
        break;
      }
    }
  }

  refresh();

  if (initialHash.indexOf("#finding-") === 0) {
    var target = document.getElementById(initialHash.slice(1));
    if (target) target.scrollIntoView();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", reveal);
  } else {
    reveal();
  }
})();
