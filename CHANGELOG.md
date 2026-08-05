# Changelog

All notable changes to Security License Lens are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.1] — Unreleased

### Added
- **Scan diff (`licenselens diff`)** — compare two scan JSON artifacts by
  `check_id`; groups new gaps, resolved, improved, worsened, unchanged, and
  confidence changes; Markdown or JSON output
- **Batch scans (`licenselens batch`)** — run one `tenants.yaml` across many
  tenants; per-tenant `reports/<slug>/<timestamp>/` output plus `index.md`;
  one failing tenant no longer aborts the batch
- **Workspace discovery (`licenselens discover-workspace`)** — enumerate
  subscriptions and Log Analytics workspaces, probe each for
  `Microsoft.SecurityInsights/alertRules`, and print Sentinel-capable ARM IDs
- **Doctor profiles (`licenselens doctor --profile`)** — `basic` (core Graph)
  is the default; `full` also probes the Defender for Endpoint API and the
  Sentinel workspace when `--workspace-resource-id` is provided
- **Auto-discovery in scans** — `run_scan(..., discover_workspaces=True)`
  selects a workspace only when exactly one Sentinel-capable workspace exists
  (otherwise warns and refuses to guess)
- **Structured output layout** — `output.build_report_dir` slug/timestamp
  nesting with a `flat=True` legacy mode

### Notes
- `diff` rank ordering mirrors engine finding priority (gap < partial <
  skipped < error < ok < not_licensed)
- Batch entries support `auth_mode` aliases (`device`, `client_secret`,
  `azure_cli`, `dry_run`)

## [0.2.0] — 2026-08-05

### Added
- **Complete 10-check pack (Session F)**
  - `sen-analytics-rule-coverage` — ARM SecurityInsights alert rules
  - `sen-ueba-not-enabled` — ARM UEBA / entity analytics settings
  - `pur-dlp-not-enforced` — Secure Score DLP/information-protection proxy
- ARM client (`https://management.azure.com`) for Sentinel
- CLI workspace binding: `--workspace-resource-id` or subscription/RG/name
- Doctor probe for Sentinel workspace when workspace ID is provided
- Dry-run demos for Sentinel + Purview; sample report updated

### Notes
- All 10 registered checks evaluate when licensed (no more `skipped` for the original pack)
- Sentinel live scans require workspace + Microsoft Sentinel Reader (or equivalent)
- MDO/MDI/Purview may still rely on Secure Score proxies

## [0.2.0b1] — 2026-08-05

### Added
- **Defender pack (Session E)**
  - `mdo-p2-policies-default` via Secure Score control signals (Safe Links/Attachments proxy)
  - `mde-onboard-gap` via Defender for Endpoint API machine inventory vs licensed units
  - `mdi-sensors-missing` via Secure Score control signals
- Secure Score collector (`SecurityEvents.Read.All`)
- MDE API client (`Machine.Read.All` on WindowsDefenderATP)
- Doctor probes for Secure Score and MDE API

### Notes
- MDO/MDI use Secure Score as a proxy when direct policy/sensor APIs are unavailable
- Sentinel and Purview checks remain registered but skipped

## [0.1.0] — 2026-08-05

First production-oriented release for **identity-first** Microsoft tenant assessments.

### Added
- Product branding: **Security License Lens** (`licenselens` CLI package)
- Entitlement catalog mapping SKUs/service plans → capabilities with plain-language outcomes
- Ten registered checks (identity, defender, sentinel, purview, endpoint)
- **Live identity evaluators**
  - `id-ca-priv-gaps` — Conditional Access MFA + legacy auth block
  - `id-idprotect-off` — risk-based CA (Identity Protection outcomes)
  - `id-pim-unused` — standing privileged roles vs PIM eligibility
  - `id-dormant-privileged` — enabled privileged users with no recent successful sign-in
- Live Microsoft Graph auth: device code, client secret, Azure CLI
- Graph client with pagination and 429/5xx retries
- Live `subscribedSkus` collection and capability resolution
- `licenselens doctor` preflight (token, organization, SKUs, CA, role assignments)
- Static HTML / JSON / Markdown reports with customer-facing copy first
- Exit codes: `0` success, `1` gaps/partial, `2` auth/config/Graph error
- Docs: app registration, permissions, architecture, comparison, contributing checks
- Scrubbed dry-run sample report under `examples/sample-report/`

### Notes
- Defender, Sentinel, and Purview checks are registered but still return `skipped` until collectors ship (v0.2 roadmap)
- Sign-in sampling for dormant privileged is page-capped; large tenants may see a truncation warning
- Findings are advisory; not a Microsoft product and not a compliance certification

## [0.1.0b3] — 2026-08-05

- Session C: PIM + dormant privileged evaluators

## [0.1.0b2] — 2026-08-05

- Session B: Conditional Access + Identity Protection evaluators

## [0.1.0b1] — 2026-08-05

- Session A: live auth + subscribed SKUs + doctor

## [0.1.0a1] — 2026-08-05

- Initial scaffold: catalog, checks YAML, dry-run engine, HTML report, plain-language layer

[0.1.0]: https://github.com/d4rk-pri0r/licenselens/releases/tag/v0.1.0
