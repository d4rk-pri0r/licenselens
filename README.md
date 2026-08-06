# Security License Lens

**See what you paid for but never turned on.**

CLI package: `licenselens` · Command: `licenselens` · Release: **v0.2.0b1**

Security License Lens detects **Microsoft security configuration debt**: high-value capabilities included in E5, Entra ID P2, Defender, Sentinel, Purview, and related SKUs that remain at default or unused.

It is **not** another generic CIS/baseline scanner. It starts from **owned entitlements** (SKUs / service plans), maps them to expected controls, and reports gaps as *you pay for X → expected Y → observed Z*.

Reports lead with **plain-language outcomes** for owners and SMBs (“stronger email protection”, “smarter sign-in rules”), then tuck product names and SKU codes into a technical section for consultants.

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

# Demo scan (no tenant required)
licenselens checks
licenselens scan -o reports
open reports/security-license-lens-report.html   # macOS
```

### Live tenant (identity pack)

```bash
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...

licenselens doctor --live --auth client_secret
licenselens scan --live --auth client_secret -o reports
```

Interactive alternative: `--auth device` (see [docs/app-registration.md](docs/app-registration.md)).

Sample dry-run output is checked in at [examples/sample-report/](examples/sample-report/).

## What is live in v0.2.0b1?

| Check ID | Workload | Live? |
|----------|----------|-------|
| `id-ca-priv-gaps` | Identity | Yes — CA MFA + legacy auth |
| `id-idprotect-off` | Identity | Yes — risk-based CA |
| `id-pim-unused` | Identity | Yes — standing roles vs PIM |
| `id-dormant-privileged` | Identity | Yes — unused privileged users |
| `mdo-p2-policies-default` | Defender | Yes — Secure Score proxy |
| `mde-onboard-gap` | Endpoint | Yes — MDE API vs licensed units |
| `mdi-sensors-missing` | Defender | Yes — Secure Score proxy |
| `sen-analytics-rule-coverage` | Sentinel | Registered (skipped) |
| `sen-ueba-not-enabled` | Sentinel | Registered (skipped) |
| `pur-dlp-not-enforced` | Purview | Registered (skipped) |

Unlicensed capabilities report `not_licensed` instead of false gaps.

## Architecture

```
SKUs / service plans → capability catalog → eligible checks
        → collectors → findings → HTML / JSON / Markdown
```

- **Catalog** (`catalog/`) — capabilities unlocked by plans/SKUs  
- **Checks** (`checks/`) — YAML definitions; community-friendly  
- **Engine** — entitlement-aware evaluation + plain-language findings  
- **Report** — portable static HTML (no server)

## Permissions

Read-only Microsoft Graph **application** permissions with admin consent.  
See [docs/permissions.md](docs/permissions.md) and [docs/app-registration.md](docs/app-registration.md).

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (no gap/partial findings) |
| 1 | Completed with gap or partial findings |
| 2 | Auth / configuration / Graph error |

## Project layout

```
catalog/           # entitlement → capability map
checks/            # YAML check definitions by workload
src/licenselens/   # CLI, auth, collectors, engine, report
templates/         # HTML report template
examples/          # sample scrubbed report
docs/              # architecture, permissions, contributing checks
tests/             # fixture-based unit tests
```

## Roadmap

- Microsoft Sentinel analytics + UEBA checks  
- Purview DLP enforcement checks  
- Direct MDO policy APIs (reduce Secure Score proxy reliance)  
- MSP multi-tenant batch mode  

## Contributing

New checks are the primary contribution path. See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/adding-a-check.md](docs/adding-a-check.md).

## Security

Report vulnerabilities privately per [SECURITY.md](SECURITY.md). This tool is **read-only** and sends no telemetry by default.

## License

[MIT](LICENSE)

## Disclaimer

Security License Lens is an independent open-source project and is **not** affiliated with, endorsed by, or sponsored by Microsoft Corporation. Findings are advisory and do not constitute a compliance certification. “Microsoft”, “Entra”, “Defender”, “Sentinel”, and “Purview” are trademarks of their respective owners.
