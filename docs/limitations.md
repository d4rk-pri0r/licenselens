# Known limitations (proud honesty)

Security License Lens is **advisory**. Confirm every finding in the Microsoft admin portals before you change production.

## Evidence boundaries

| Area | What we can read | What we cannot |
|------|------------------|----------------|
| Identity (CA, PIM, roles, sign-ins) | Graph (app-only or device code) | Intent of every exclusion group |
| Endpoint (MDE onboard) | MDE API machine inventory | Full health of every sensor |
| Email (MDO Safe Links / Safe Attachments / presets) | **Nothing via Graph** | Policy config is Exchange Online PowerShell only |
| MDI sensors | Secure Score proxy only (if opted) | Direct sensor health API in this tool |
| Purview DLP | Secure Score proxy (+ best-effort) | Full Purview policy surface app-only |
| Sentinel | ARM analytics rules + UEBA when workspace given | Full content-hub depth |

## Email pack (default off)

- Default packs are **identity + endpoint**.
- Email is **off** the default card because there is no Graph read API for MDO policy configuration (Microsoft Q&A + docs: PowerShell / portal only).
- Opt-in degraded path: `--allow-email-proxy` uses Secure Score control scores, labeled proxy, subject to strict proxy quality policy, **never** rolls up to fully working.

## Proxies and confidence

- Proxy findings are capped: they do not emit a clean “fully working” outcome under strict proxy mode.
- Always re-check labeled proxy items in the portal.

## Sampling

- Sign-in lookbacks are paged (default ~90 days, page budget). Large tenants may truncate; findings note when the sample looks truncated.
- MDE machine counts may truncate on very large estates.

## Auth / permissions

- Device code can be blocked by Conditional Access → use app-only (see MSP docs).
- Missing permissions produce **partial cards** with limitations, not silent empty success.
- Doctor marks optional probes (MDE, email unreadability, Secure Score) as warnings so identity-ready still means ready.

## What this tool is not

- Not a compliance certification (CIS, CISA, SOC2).
- Not a CSPM that remediates.
- Not a license cost optimizer.
- No product telemetry by default.
- No Huntress (or other vendor) branding in-product.

## Stability note

Check IDs stay stable across minor releases unless a changelog note says otherwise. Prefer additive fields in JSON for MSP glue.

## Verification scope (what runs where)

The release gate is `scripts/release_gate.py`, a reproducible, fail-closed runner
whose ledger records every quality command it executes and every step it defers.

- **Runs on Linux/macOS:** Ruff lint/format, the full pytest suite with a 72%
  coverage floor, the Playwright Chromium report suite (including the
  no-network/CSP/a11y contracts), the coverage-manifest validator, MkDocs strict
  build + codespell + lychee, wheel/sdist build, installed-wheel smoke, the
  Pester bridge and installer suites, the release/CI workflow static guards, and
  the deterministic two-run reference docs and sample report.
- **Deferred to Windows CI:** the PyInstaller one-folder exe and its ZIP —
  PyInstaller is not a cross-compiler, so the frozen artifact is built only on a
  Windows runner (`windows-ci.yml`); its data/one-folder/archive contracts are
  locked cross-platform by `tests/test_windows_packaging.py`.
- **Deferred to the operator:** live-tenant execution. The controlled live-lab is
  dry-run validated against fake backends (`scripts/lab_runner.py`) and no real
  Microsoft tenant, credential, UPN, or resource identifier is ever touched or
  stored here.
