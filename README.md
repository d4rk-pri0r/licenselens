# Security License Lens

**The security you already own (and ignore).**

CLI: `licenselens` · Release: **v0.2.x → talk-ready**

Security License Lens finds **Microsoft security configuration debt**: high-value capabilities in E5, Entra ID P2, Defender, and related SKUs that stay at default or unused. It starts from **owned entitlements**, maps them to expected controls, and reports gaps as *you pay for X → expected Y → observed Z*.

> Sample card (dry-run Contoso): [examples/sample-report/](examples/sample-report/)

## Monday path (start here)

```bash
# One-command offline demo → HTML card
pipx install licenselens   # or: pip install -e ".[dev]"
licenselens demo

# Your own tenant (read-only device code)
licenselens quickstart
```

Default talk packs are **identity + endpoint**. Email policy config is not readable via Graph (PowerShell-only); use `--allow-email-proxy` only if you explicitly want a labeled Secure Score degraded path.

### Live / MSP

```bash
licenselens doctor --live --auth client_secret
licenselens scan --live --auth client_secret -o reports
licenselens batch tenants.yaml -o reports
```

## Why Security License Lens?

| Tool | Optimizes for |
|------|----------------|
| [ScubaGear](https://github.com/cisagov/ScubaGear) | CISA baseline compliance |
| [Maester](https://github.com/maester365/maester) | Continuous config tests (Pester) |
| [Monkey365](https://github.com/silverhack/monkey365) | Broad CSPM / CIS-style assessment |
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

## Full check pack (v0.2.0)

| Check ID | Workload | Live evaluation |
|----------|----------|-----------------|
| `id-ca-priv-gaps` | Identity | Conditional Access MFA + legacy auth |
| `id-idprotect-off` | Identity | Risk-based CA |
| `id-pim-unused` | Identity | Standing roles vs PIM eligibility |
| `id-dormant-privileged` | Identity | Unused privileged users |
| `mdo-p2-policies-default` | Defender | Off default packs; opt-in `--allow-email-proxy` only |
| `mde-onboard-gap` | Endpoint | MDE API vs licensed units |
| `mdi-sensors-missing` | Defender | Secure Score proxy |
| `sen-analytics-rule-coverage` | Sentinel | ARM analytics rules (workspace required) |
| `sen-ueba-not-enabled` | Sentinel | ARM UEBA/entity analytics settings |
| `pur-dlp-not-enforced` | Purview | Secure Score DLP proxy |

Unlicensed capabilities report `not_licensed` instead of false gaps.

### Known limitations

See [docs/limitations.md](docs/limitations.md) for the full list. Short version:

- **Email pack off default** — no Graph API for MDO policy config (PowerShell-only); `--allow-email-proxy` is opt-in and labeled
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

See [docs/permissions.md](docs/permissions.md) and [docs/app-registration.md](docs/app-registration.md).

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (no gap/partial findings) |
| 1 | Completed with gap or partial findings |
| 2 | Auth / configuration / API error |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/adding-a-check.md](docs/adding-a-check.md).

## Security

[SECURITY.md](SECURITY.md) — read-only, no telemetry by default.

## License

[MIT](LICENSE)

## Disclaimer

Security License Lens is an independent open-source project and is **not** affiliated with, endorsed by, or sponsored by Microsoft Corporation. Findings are advisory. “Microsoft”, “Entra”, “Defender”, “Sentinel”, and “Purview” are trademarks of their respective owners.
