# Security License Lens

**The security you already own (and ignore).**

LicenseLens turns your Microsoft 365 entitlements into a plain-English, prioritized fix list: it checks whether the controls you already pay for are actually on, and shows you what to fix first.

CLI: `licenselens` · Requires Python 3.12+

> Documentation: [d4rk-pri0r.github.io/licenselens](https://d4rk-pri0r.github.io/licenselens/)

Security License Lens finds **Microsoft security configuration debt**: high-value capabilities in E5, Entra ID P2, Defender, and related SKUs that stay at default or unused. It starts from **owned entitlements**, maps them to expected controls, and reports gaps as *you pay for X → expected Y → observed Z*.

> Sample report (dry-run): [examples/sample-report/](https://github.com/d4rk-pri0r/licenselens/tree/main/examples/sample-report)

## Quick start

```bash
# One-command offline demo → HTML report
pipx install licenselens   # or: pip install -e ".[dev]"
licenselens demo

# Interactive scan: prompts for anything missing (TTY)
licenselens scan

# Or jump straight to a live tenant walkthrough
licenselens quickstart
```

In a terminal, `licenselens scan` asks demo vs live tenant, sign-in method, and
other missing options. Flags and `AZURE_*` env vars always win when set.
Non-interactive environments default to dry-run (or exit with a clear error on
`--live` without credentials).

Default priority packs are **identity + endpoint**. They shape the headline rollup and top actions; enabled checks still evaluate unless `--workload` filters them. Email policy config is not readable via Graph (PowerShell-only); use `--allow-email-proxy` only if you explicitly want a labeled Secure Score degraded path.

### Live / MSP

```bash
licenselens doctor --live --auth client_secret
licenselens scan --live --auth client_secret -o reports
licenselens batch tenants.yaml -o reports
```

## What it looks like

![report hero](images/report-hero.png)

*The dashboard: what you own, what's working, and what to fix first.*

![report findings](images/report-findings.png)

*Every finding shows its evidence and a direct link to the admin page.*

<p align="center">
  <img src="images/report-mobile.png" width="375" alt="The report on mobile">
  <br>
  <em>The same report at mobile width.</em>
</p>

## A concrete example

The most common finding, `id-ca-priv-gaps`:

- **You pay for** Microsoft 365 E5, so Conditional Access is licensed for every user.
- **We expect** MFA and legacy-auth blocking enforced through a CA policy.
- **We observed** zero Conditional Access policies → the report marks the tenant `EXPOSED`.
- **Do this** → enable an MFA CA policy (a few hours of work). The gap closes on the next scan.

## Why Security License Lens?

| Tool | Optimizes for |
|------|----------------|
| [ScubaGear](https://github.com/cisagov/ScubaGear) | CISA baseline compliance |
| [Maester](https://github.com/maester365/maester) | Continuous config tests (Pester) |
| Microsoft Secure Score | Score + recommendations (not SKU-gated) |
| License waste scripts | Seat assignment efficiency |
| **Security License Lens** | **Owned SKUs → expected high-value controls → unused/default gaps** |

### Diff, discovery, and batch

```bash
# Compare two scan JSON artifacts by check_id
licenselens diff reports/before.json reports/after.json -o reports/diff.md

# Discover Sentinel-capable workspaces (prints ARM resource IDs)
licenselens discover-workspace --auth client_secret

# Multi-tenant scans from tenants.yaml (per-tenant reports + index.md)
licenselens batch tenants.yaml -o reports
```

## Full check pack (v0.3.0)

| Check ID | Workload | Live evaluation |
|----------|----------|-----------------|
| `id-ca-priv-gaps` | Identity | Conditional Access MFA + legacy auth |
| `id-idprotect-off` | Identity | Risk-based CA |
| `id-pim-unused` | Identity | Standing roles vs PIM eligibility |
| `id-dormant-privileged` | Identity | Unused privileged users |
| `id-security-defaults-on` | Identity | Security defaults ON despite CA licenses |
| `id-access-reviews-unused` | Identity | Access Reviews licensed but never configured |
| `mdo-p2-policies-default` | Defender | Off default packs; opt-in `--allow-email-proxy` only |
| `mde-onboard-gap` | Endpoint | MDE API vs licensed units |
| `mdi-sensors-missing` | Defender | Secure Score proxy |
| `sen-analytics-rule-coverage` | Sentinel | ARM analytics rules (workspace required) |
| `sen-ueba-not-enabled` | Sentinel | ARM UEBA/entity analytics settings |
| `pur-dlp-not-enforced` | Purview | Secure Score DLP proxy |

Unlicensed capabilities report `not_licensed` instead of false gaps.

### Known limitations

See [limitations](limitations.md) for the full list. Short version:

- **Email pack off by default** — no Graph API for MDO policy config (PowerShell-only); `--allow-email-proxy` is opt-in and labeled
- MDI / Purview may still use **Secure Score proxies** (starter packs)
- Sentinel needs a **workspace ARM ID** + Azure RBAC
- Sign-in / MDE inventories may **truncate** on huge tenants
- Findings are **advisory**, not a compliance certification
- **No product telemetry** by default

## Architecture

```
SKUs / service plans → capability catalog → eligible checks
        → collectors (Graph / MDE / ARM) → findings → HTML / JSON / Markdown
```

## Permissions

See [permissions](permissions.md) and [app registration](app-registration.md).

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (no gap/partial findings) |
| 1 | Completed with gap or partial findings |
| 2 | Auth / configuration / API error |

## Contributing

See [Contributing](contributing.md) and [adding a check](adding-a-check.md).

## Security

[Security](security.md) — read-only, no telemetry by default.

## License

[MIT](https://github.com/d4rk-pri0r/licenselens/blob/main/LICENSE)

## Disclaimer

Security License Lens is an independent open-source project and is **not** affiliated with, endorsed by, or sponsored by Microsoft Corporation. Findings are advisory. “Microsoft”, “Entra”, “Defender”, “Sentinel”, and “Purview” are trademarks of their respective owners.
