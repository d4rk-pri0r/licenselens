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

Profile schema fields such as `redact_tenant_ids` are accepted on assessment
profiles but are **not** applied to HTML/JSON/MD report output today. Do not
assume JSON is stripped of tenant identifiers.

The HTML report may also embed report JSON for offline interactivity
(`window.LICENSELENS_REPORT_JSON`); handle HTML exports with the same care.

## The HTML report

- **Top card** — capability rollup (% realized), ranked moves by impact/exposure/effort, and an `EXPOSED` chip for legacy auth / MFA-less global admin.
- **Findings** — every finding ties observed evidence to the expected control and the capability it maps to, with plain-language next steps.
- **Evidence drawers** — provenance, collection health, limitations, entitlement explanation, waiver state, and remediation.
- **Charts** — local SVG with equivalent tables and text for assistive tech.
- **Export** — filtered findings to JSON or CSV, and print without network or third-party runtime.
- **Offline** — no CDN, external fonts, icon packages, or network requests at view time.

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

The report loads **no external font, CDN, icon package, image, or network
request**. Charts, icons, and styling are all local; a Content-Security-Policy
blocks injected scripts without blocking the app's own assets. Offline rendering
does not mean the JSON is free of tenant data — see [Sensitivity](#sensitivity)
above. See [Limitations](limitations.md) for what the report can and cannot tell
you.
