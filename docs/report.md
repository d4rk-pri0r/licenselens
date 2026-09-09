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

## Action-plan export (`--export`)

`scan`, `demo`, and `quickstart` accept `--export action-plan|csv|json` to write
a remediation action plan beside the reports:

| `--export` value | Output file | Format |
|------------------|-------------|--------|
| `action-plan` | `action-plan.csv` | Deterministic CSV (fixed column order, RFC 4180 escaping) |
| `csv` | `action-plan.csv` | Same deterministic CSV |
| `json` | `action-plan.json` | Plain JSON array of the same rows |

```bash
licenselens scan --live --auth client_secret --profile identity -o reports --export action-plan
licenselens scan --live --auth client_secret -o reports --export json
```

The action-plan rows carry structured activation-backlog metadata (§18): each
row exposes the security `capability`, the `entitlement` that unlocks it, the
`severity`/`risk`, the `effort` and a deterministic `timeline`, an
`implementation_category` (quick configuration / moderate deployment /
multi-team project / manual investigation), the `reason` (remediation), the
`current_evidence` (data sources), an authoritative Microsoft `reference`, a
`manual_validation_needed` flag, and `customer_next_step` / `deep_link`. The
serialized text is threaded through the same redaction pipeline as the other
report surfaces, so tenant ids, UPN-like strings, and (when enabled) tenant
domains are stripped before the file is written.

This export is the **activation backlog**: convert any GAP into a
customer/MSP work item (capability → current evidence → desired state → risk →
entitlement → reference → category → manual-validation flag).

## Compliance mappings in the findings explorer

Every finding carries optional compliance/attack-surface **mappings** (for
example `{"nist": ["AC-2"], "mitre": ["T1078"]}`) sourced from the check YAML.
In the HTML report's **Explore everything** view:

- Each finding row shows a **Compliance** meta line listing the mapped
  frameworks and controls (e.g. `NIST: AC-2; MITRE: T1078`).
- A **compliance mappings** filter facet (`Mapped` / `Unmapped`) lets you
  isolate controls that carry NIST or MITRE references from those that do not.
  Selecting several values in a group matches any of them; different groups
  combine.

## Merged multi-tenant dashboard (`merge-reports`)

`licenselens merge-reports <dir> -o <out>` inlines every tenant's
`security-license-lens-report.json` into **one** single-file HTML dashboard with
a client-side tenant switcher. It is the natural companion to `batch`: point it
at a batch output root to get a single cross-tenant view.

```bash
licenselens batch tenants.yaml -o reports --live
licenselens merge-reports reports -o reports/merged.html
```

The merged view reads a multi-tenant data shape
(`window.LICENSELENS_TENANTS = {slug: <tenant data>}`) and swaps the active
tenant entirely client-side with zero network requests. It applies the **union**
of every tenant's redaction targets, so a cross-tenant identifier (tenant A's id
or UPN appearing inside tenant B's payload, or vice versa) is scrubbed from
every region. See [CLI reference](cli.md) for the full flag catalog.

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

The report is a self-contained HTML file. It reads top to bottom in five
sections:

- **Where you stand** — the first screen: lens mark + product name, section nav, one
  posture figure (`<percent>% realized`, bound to
  `capability_rollup.realized_percent` — never hardcoded), a distribution bar,
  one sentence, and a link to the next actions. Scan metadata lives in the
  footer. The accounting strip (owned / met criteria / licensed vs evaluated)
  sits behind "How we got here".
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

- **Motion** — one opening animation (500–1000ms total: identity fade-in,
  count-up, gauge draw, staggered reveals); after it settles: one-shot section
  reveals, constellation nodes resolving from neutral to their
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
