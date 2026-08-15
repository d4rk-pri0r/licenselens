# Report and export

Every scan writes a static, offline-first report in three formats next to each
other, plus a deterministic archive on request.

## Output formats

```bash
licenselens scan -o reports
```

writes, per scan:

| File | Purpose |
|------|---------|
| `security-license-lens-report.html` | Self-contained dashboard; opens in any browser, no network |
| `security-license-lens-report.json` | Portable machine-readable artifact for diffing and archiving |
| `security-license-lens-report.md` | Plain Markdown summary |

Add `--report-archive` to also write a deterministic offline ZIP beside the
HTML/JSON.

## The HTML report

- **Top card** — capability rollup (% realized), ranked moves by impact/exposure/effort, and an `EXPOSED` chip for legacy auth / MFA-less global admin.
- **Findings** — every finding ties observed evidence to the expected control and the capability it maps to, with plain-language next steps.
- **Evidence drawers** — provenance, collection health, limitations, entitlement explanation, waiver state, and remediation.
- **Charts** — local SVG with equivalent tables and text for assistive tech.
- **Export** — filtered findings to JSON or CSV, and print without network or third-party runtime.

## Diffing two scans

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
recorded in the index and the batch continues.

## Offline and privacy-safe

The report loads **no external font, CDN, icon package, image, or network
request**. Charts, icons, and styling are all local; a Content-Security-Policy
blocks injected scripts without blocking the app's own assets. See
[Limitations](limitations.md) for what the report can and cannot tell you.
