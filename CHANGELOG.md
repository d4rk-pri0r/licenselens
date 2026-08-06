# Changelog

All notable changes to Security License Lens are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
