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

## Email pack (talk default)

- Default talk packs are **identity + endpoint**.
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

## Freeze note

After the talk freeze date, check IDs stay stable unless a diff note is published. Prefer additive fields in JSON for MSP glue.
