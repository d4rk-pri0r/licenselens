# Security License Lens

**See what you paid for but never turned on.**

CLI package: `licenselens` · Command: `licenselens` · Release: **v0.2.0**

Security License Lens detects **Microsoft security configuration debt**: high-value capabilities included in E5, Entra ID P2, Defender, Sentinel, Purview, and related SKUs that remain at default or unused.

It is **not** another generic CIS/baseline scanner. It starts from **owned entitlements** (SKUs / service plans), maps them to expected controls, and reports gaps as *you pay for X → expected Y → observed Z*.

Reports lead with **plain-language outcomes** for owners and SMBs, then tuck product names and SKU codes into a technical section for consultants.

## Why Security License Lens?

| Tool | Optimizes for |
|------|----------------|
| [ScubaGear](https://github.com/cisagov/ScubaGear) | CISA baseline compliance |
| [Maester](https://github.com/maester365/maester) | Continuous config tests (Pester) |
| [Monkey365](https://github.com/silverhack/monkey365) | Broad CSPM / CIS-style assessment |
| Microsoft Secure Score | Score + recommendations (not SKU-gated) |
| License waste scripts | Seat assignment efficiency |
| **Security License Lens** | **Owned SKUs → expected high-value controls → unused/default gaps** |

## Quick start

```bash
cd licenselens
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

licenselens checks
licenselens scan -o reports
open reports/security-license-lens-report.html
```

### Live tenant

```bash
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...

licenselens doctor --live --auth client_secret
licenselens scan --live --auth client_secret -o reports

# Sentinel checks (workspace required)
licenselens scan --live --auth client_secret \
  --workspace-resource-id "/subscriptions/.../resourceGroups/.../providers/Microsoft.OperationalInsights/workspaces/..." \
  -o reports
```

Sample dry-run output: [examples/sample-report/](examples/sample-report/).

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
| `mdo-p2-policies-default` | Defender | Secure Score proxy (Safe Links/Attachments) |
| `mde-onboard-gap` | Endpoint | MDE API vs licensed units |
| `mdi-sensors-missing` | Defender | Secure Score proxy |
| `sen-analytics-rule-coverage` | Sentinel | ARM analytics rules (workspace required) |
| `sen-ueba-not-enabled` | Sentinel | ARM UEBA/entity analytics settings |
| `pur-dlp-not-enforced` | Purview | Secure Score DLP proxy |

Unlicensed capabilities report `not_licensed` instead of false gaps.

### Known limitations

- MDO, MDI, and Purview DLP may use **Secure Score proxies** when direct policy APIs are unavailable
- Sentinel requires **workspace ARM ID** + Azure RBAC (Microsoft Sentinel Reader)
- MDE machine counts may truncate on very large tenants
- Findings are **advisory**, not a compliance certification

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
