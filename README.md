# Security License Lens

**See what you paid for but never turned on.**

CLI package name: `licenselens` · Command: `licenselens`

Security License Lens detects **Microsoft security configuration debt**: high-value capabilities included in E5, Entra ID P2, Defender, Sentinel, Purview, and related SKUs that remain at default or unused.

It is **not** another generic CIS/baseline scanner. It starts from **owned entitlements** (SKUs / service plans), maps them to expected controls, and reports gaps as *you pay for X → expected Y → observed Z*.

Reports lead with **plain-language outcomes** for owners and SMBs (“stronger email protection”, “smarter sign-in rules”), then tuck product names and SKU codes into a technical section for consultants.

> Status: **v0.1.0b2** — live Graph auth, SKUs, and first identity evaluators (Conditional Access + Identity Protection via CA risk policies).

## Why Security License Lens?

| Tool | Optimizes for |
|------|----------------|
| [ScubaGear](https://github.com/cisagov/ScubaGear) | CISA baseline compliance |
| [Maester](https://github.com/maester365/maester) | Continuous config tests (Pester) |
| [Monkey365](https://github.com/silverhack/monkey365) | Broad CSPM / CIS-style assessment |
| Microsoft Secure Score | Score + recommendations (not SKU-gated) |
| License waste scripts | Seat assignment efficiency |
| **Security License Lens** | **Owned SKUs → expected high-value controls → unused/default gaps** |

Audience: MSPs, consultants, security architects, and SecOps leads who need a sharp **security + value** narrative for “licensed but minimally configured” tenants.

## Quick start

```bash
# From a clone
cd licenselens
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# List registered checks
licenselens checks

# Dry-run scan → static HTML dashboard (+ JSON + Markdown)
licenselens scan -o reports
open reports/security-license-lens-report.html   # macOS

# Live entitlements (app-only)
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
licenselens doctor --live --auth client_secret
licenselens scan --live --auth client_secret -o reports
```

See [docs/app-registration.md](docs/app-registration.md) for Entra app setup. Configuration control checks beyond SKU→capability mapping are not fully live yet.

## v0.1 check pack (registered)

| ID | Workload | Theme |
|----|----------|--------|
| `id-pim-unused` | Identity | PIM not operationalized |
| `id-ca-priv-gaps` | Identity | Privileged CA / legacy auth gaps |
| `id-idprotect-off` | Identity | Identity Protection off / report-only |
| `id-dormant-privileged` | Identity | Dormant privileged identities |
| `mdo-p2-policies-default` | Defender | MDO P2 not broadly enforced |
| `mde-onboard-gap` | Endpoint | MDE licensed vs onboarded gap |
| `mdi-sensors-missing` | Defender | MDI sensors missing / unhealthy |
| `sen-analytics-rule-coverage` | Sentinel | Thin analytics rule coverage |
| `sen-ueba-not-enabled` | Sentinel | UEBA not enabled |
| `pur-dlp-not-enforced` | Purview | DLP not enforced |

**Live evaluators today:** `id-ca-priv-gaps`, `id-idprotect-off`.  
Other licensed checks report `skipped` until their collectors ship; unlicensed ones report `not_licensed`.

## Architecture (MVP)

```
SKUs / service plans → capability catalog → eligible checks
        → collectors → findings → HTML / JSON / Markdown
```

- **Catalog** (`catalog/`) — capabilities unlocked by plans/SKUs  
- **Checks** (`checks/`) — YAML definitions; community-friendly  
- **Engine** — only runs (or marks) checks the tenant is entitled to  
- **Report** — portable static HTML (no server)

## Permissions

Read-only Microsoft Graph application permissions are planned for live mode. See [docs/permissions.md](docs/permissions.md).

## Project layout

```
catalog/           # entitlement → capability map
checks/            # YAML check definitions by workload
src/licenselens/   # CLI, auth, collectors, engine, report
templates/         # HTML report template
docs/              # architecture, contributing checks, comparison
tests/             # fixture-based unit tests
```

## Contributing

New checks are the primary contribution path. See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/adding-a-check.md](docs/adding-a-check.md).

## Security

Report vulnerabilities privately per [SECURITY.md](SECURITY.md). Security License Lens is intended to be **read-only**.

## License

[MIT](LICENSE)

## Disclaimer

Security License Lens is an independent open-source project and is **not** affiliated with, endorsed by, or sponsored by Microsoft Corporation. “Microsoft”, “Entra”, “Defender”, “Sentinel”, and “Purview” are trademarks of their respective owners.
