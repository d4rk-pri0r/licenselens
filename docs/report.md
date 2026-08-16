# Report and export

Every scan writes a static, offline-first report in three formats, plus a
deterministic archive on request.

## Output layout

### Single-tenant: flat into `--output-dir`

`scan`, `demo`, and `quickstart` write report files **flat** into
`-o` / `--output-dir` (default `reports`). There is no per-tenant slug or
timestamp subdirectory for these commands.

```bash
licenselens scan -o reports
licenselens demo -o reports
licenselens quickstart -o reports
```

| File | Purpose |
|------|---------|
| `security-license-lens-report.html` | Self-contained dashboard; opens in any browser, no network |
| `security-license-lens-report.json` | Portable machine-readable artifact for diffing and archiving |
| `security-license-lens-report.md` | Plain Markdown summary |

Example paths after a demo run:

```text
reports/security-license-lens-report.html
reports/security-license-lens-report.json
reports/security-license-lens-report.md
```

### Batch only: `reports/<slug>/<timestamp>/`

Only `licenselens batch` nests output under a tenant **slug** and run
**timestamp**, and writes a summary `index.md` at the batch output root:

```text
reports/<slug>/<timestamp>/security-license-lens-report.html
reports/<slug>/<timestamp>/security-license-lens-report.json
reports/<slug>/<timestamp>/security-license-lens-report.md
reports/index.md
```

See [MSP batch](msp-batch.md).

## Report archive (`--report-archive`)

Add `--report-archive` on `scan` / `demo` / `quickstart` / `batch` (or set
`report_archive: true` per tenant in `tenants.yaml`) to also write
`security-license-lens-report.zip` beside the HTML/JSON/MD files. The ZIP is a
deterministic offline bundle of the same report artifacts.

## Sensitivity

JSON and ZIP reports embed **`tenant_id`**, finding **evidence**, and related
tenant metadata. Treat them as **sensitive**. Do not commit live report
artifacts to public repos or share them without the same controls you use for
tenant configuration exports.

Profile schema fields such as `redact_tenant_ids` are accepted on profiles
but are **not** applied to HTML/JSON/MD report output today. Do not
assume JSON is stripped of tenant identifiers.

The HTML report may also embed report JSON for offline interactivity
(`window.LICENSELENS_REPORT_JSON`); handle HTML exports with the same care.

## The HTML report

The report is a dark, offline-first dashboard — **"Warm Charcoal"**: a warm
charcoal canvas (`#191714`) with muted, warm-neutral surfaces, a
champagne-ivory identity accent, and a semantic ramp (red / amber / green)
reserved for status alone. The only chromatic color in the UI is semantic; blue
in the page comes from the branded Microsoft workload marks only. It reads top
to bottom in five sections:

- **Where you stand** — the signature opening sequence: org / tenant identity,
  assessment meta, a count-up posture figure (`<percent>% realized`, bound to
  `capability_rollup.realized_percent` — never hardcoded), a radial realization
  gauge with an operational-distribution bar, the most important implication
  sentence, and the top actions. Section A is hierarchy-first: **one** dominant
  3.5rem posture figure with a supporting stat strip, not a grid of equal metric
  cards.
- **What you're paying for** — your owned SKUs and a capability
  **constellation**: a deterministic, labeled field of every owned capability
  grouped by workload and colored by status. Group captions are buttons that
  cross-filter the page, and every caption and capability row carries the
  workload's branded Microsoft icon next to its always-visible text label.
- **What matters most** — the top ranked moves: title, effort, why it matters,
  and the concrete next step with a link to the admin page.
- **Why LicenseLens believes this** — every finding as a six-slot "belief block"
  (Expected, Observed, Why it matters, Recommended action, Evidence, Admin
  destination) with a technical evidence drawer.
- **Explore everything** — search, multi-facet filters, sort, pagination, the
  data-visualization figures, and CSV/JSON export over every assessed control
  (interactive view).

- **Motion is information design** — one signature opening sequence (500–1000ms
  total: identity fade-in, count-up, gauge draw, staggered reveals), then calm:
  one-shot section reveals, constellation nodes resolving from neutral to their
  status color, and ≤150ms interactive feedback. Nothing loops; nothing is
  ambient; `prefers-reduced-motion` renders the instant final state with zero
  information loss.
- **Progressive disclosure** — native `<details>`: summary → explanation →
  evidence, each level unfolding in place beneath the article. The single-file
  renderer works with JavaScript disabled.
- **Offline** — no CDN, external fonts, icon packages, chart libraries, or
  network requests at view time; styling, glyphs, and the constellation are
  inline. The single-file report inlines its branded workload icons as SVG; the
  bundle app ships them as hashed local `<img>` assets. Both renderers always
  pair each icon with a visible text label.
- **Print** — inverts to light ink, expands every disclosure, and turns each
  chart's sr-only data table into a visible textual fallback; export filtered
  findings to JSON or CSV, or print to PDF, without any network or third-party
  runtime.

A scrubbed dry-run tenant rendered in the v2 design ships at
`examples/sample-report/security-license-lens-report.html`.

## Diffing two scans

Point `diff` at two JSON artifacts (often from separate `-o` directories):

```bash
licenselens diff \
  reports/before/security-license-lens-report.json \
  reports/after/security-license-lens-report.json \
  -o reports/diff.md
```

The diff groups checks into **new gaps**, **resolved**, **improved**,
**worsened**, and **unchanged**, and lists confidence changes. Use `-o diff.json`
for a machine-readable version.

## Batch index

`licenselens batch tenants.yaml -o reports` writes per-tenant reports under
`reports/<slug>/<timestamp>/` plus a summary `index.md`. A failing tenant is
recorded in the index and the batch continues. The index sorts **exposed**
tenants first.

## Offline and privacy-safe

The report loads **no external font, CDN, icon package, chart library, or
network request**. Visualizations, glyphs, and styling are all local — the
single-file report inlines its branded workload icons as SVG, and the bundle
ships them as hashed local assets. A Content-Security-Policy
blocks injected scripts without blocking the app's own assets. Offline rendering
does not mean the JSON is free of tenant data — see [Sensitivity](#sensitivity)
above. See [Limitations](limitations.md) for what the report can and cannot tell
you.
