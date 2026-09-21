# Security License Lens

**Know which security controls you already pay for — and which of them are actually on.**

You pay for E5, Entra ID P2, Defender, and related SKUs. A lot of the useful
controls in those SKUs never get turned on. LicenseLens maps what you own to
the controls that should be on, collects evidence from Microsoft APIs, applies
deterministic evaluators, and reports the gaps: you pay for X, we expected Y,
we observed Z.

Local execution · read-only collection · deterministic verdicts · no LLM in
the verdict path · no product telemetry by default

CLI: `licenselens` · Requires Python 3.12+ · MIT

> Documentation: [d4rk-pri0r.github.io/licenselens](https://d4rk-pri0r.github.io/licenselens/)
> · [Open a full sample report](https://d4rk-pri0r.github.io/licenselens/sample-report.html)

## Quick start

```bash
# One-command offline demo → HTML report (macOS / Linux / Windows)
pipx install licenselens
licenselens demo --open
```

The offline demo needs no tenant, no credentials, and no Microsoft account.
It writes an HTML report plus portable JSON and Markdown summaries, and opens
the report in your browser.

![report opening](docs/images/report-hero.png)

*The report opens on one number, what it means, and the first ranked action.
Every claim below it can be opened: findings carry evidence, confidence, and
limitations, and the technical ledger shows exactly how each verdict was
derived.*

On Windows the same pipx install works: the PyPI wheel bundles the PowerShell
collector bridge since 0.4.0, so the email pack and all PowerShell-only
collectors run from a plain pipx install (Python 3.12+ and pipx required —
see the [Windows guide](docs/windows.md)).

## What the assessment answers

```text
owned entitlement → expected state → observed evidence → qualified finding → ranked next step
```

A finding is not a hunch. Every row names the check that produced it, the
evidence it read (direct from the control itself, a labeled proxy, or
operator-confirmed), a confidence level, and its limitations. Missing evidence
stays missing: an API failure, a missing permission, or an unknown
entitlement never becomes a clean pass or a false gap.

## A concrete example (from the offline demo)

The `id-ca-priv-gaps` finding:

- **You pay for** Microsoft 365 E5, so Conditional Access is licensed for
  every user.
- **We expect** MFA enforced and legacy-authentication sign-ins blocked
  through Conditional Access.
- **We observed** three enabled CA policies covering MFA for privileged
  accounts, and none that block legacy authentication — a `partial` finding
  with high confidence, whose evidence block names every policy it counted.
- **Do this** → add a legacy-authentication block policy. The next scan shows
  the change, and `licenselens diff` proves before/after.

## How it works

```text
your credentials, or a deterministic offline fixture
  → entitlements (subscribed SKUs / service plans)
  → capability catalog (what each SKU is supposed to unlock)
  → read-only collectors (Graph / MDE / ARM / DNS / Secure Score / PowerShell bridge)
  → normalized evidence
  → deterministic evaluators
  → uncertainty policy (proxy, partial, truncated, and failed evidence demoted, never flattened)
  → rollup + ranking
  → offline HTML / JSON / Markdown
```

There is no hosted control plane. The CLI runs locally with your credentials
and writes artifacts to disk. Collection is read-only at the transport level:
Graph requests are allowlisted to safe methods and paths, the Azure and MDE
clients issue GETs only, and the PowerShell bridge blocks write verbs through
a central read-command wrapper. It never changes tenant configuration.

Deeper reading: [component map](docs/component-map.md) ·
[architecture](docs/architecture.md) ·
[methodology](docs/methodology/assessment-model.md)

## Why Security License Lens?

| Tool | Optimizes for |
|------|----------------|
| [ScubaGear](https://github.com/cisagov/ScubaGear) | CISA baseline compliance |
| [Maester](https://github.com/maester365/maester) | Continuous config tests (Pester) |
| [Monkey365](https://github.com/silverhack/monkey365) | Broad CSPM / CIS-style assessment |
| Microsoft Secure Score | Score + recommendations (not SKU-gated) |
| License waste scripts | Seat assignment efficiency |
| **Security License Lens** | **Owned SKUs → expected high-value controls → unused/default gaps** |

### Live scans, batch, and diff

```bash
licenselens doctor --live --auth client_secret            # preflight: auth + permissions
licenselens scan --live --auth client_secret -o reports   # start with the smallest useful scope
licenselens batch tenants.yaml -o reports                 # multi-tenant: per-tenant reports + index
licenselens diff reports/before.json reports/after.json -o reports/change.md
```

Live scanning needs an Entra app registration with read-only permissions and
admin consent: [app registration guide](docs/app-registration.md). Credentials
come from `AZURE_*` environment variables, never from report files or source
code. Scan artifacts can contain tenant IDs and evidence, so treat every
output file as sensitive.

Exit codes are CI-friendly: `0` clean, `1` gaps or partial findings (work to
do, not a tool failure), `2` auth/config/API error. Default priority packs are
**identity + endpoint**; they shape the headline rollup and top actions, while
all enabled checks still evaluate. Email policy config is not readable via
Graph (PowerShell-only); `--allow-email-proxy` is an opt-in, labeled Secure
Score degraded path.

## Use it from an AI assistant

LicenseLens ships an MCP server (stdio, local, read-only) so Claude Code,
Copilot, or Cursor can run an assessment and reason over the same structured
findings the CLI emits, including ranked next steps and license constraints.
The verdicts stay deterministic: the assistant reads them; it does not
produce them.

```json
{ "mcpServers": { "licenselens": {
    "command": "uvx", "args": ["--from", "licenselens[mcp]", "licenselens", "mcp"] } } }
```

See [docs/mcp.md](docs/mcp.md) for host setup and live-tenant credentials.

## What's in the pack (v0.4.0)

**170 checks** · **31 capabilities** · **11 profiles** · **135** pinned SCuBA coverage rows

Checks run as **direct**, **proxy**, **manual** (you confirm), or **dynamic**
(direct first, Secure Score only if direct is missing). The report records
which mode actually ran. Unlicensed capabilities report `not_licensed` instead
of false gaps.

The generated reference is the authoritative catalog (do not trust a partial
copy here):

- [Check reference](docs/reference/checks.md) — collector, support state, evaluator, capabilities, evidence keys
- [Capabilities](docs/reference/capabilities.md) · [Profiles](docs/reference/profiles.md) · [Permissions](docs/reference/permissions.md) · [Coverage](docs/reference/coverage.md)
- Machine-readable: [reference.json](docs/reference/reference.json) · [manifest.json](docs/reference/manifest.json)

### Known limitations

See [docs/limitations.md](docs/limitations.md) for the full list. Short version:

- **Email pack off by default** — no Graph API for MDO policy config (PowerShell-only); `--allow-email-proxy` is opt-in and labeled (dynamic / Secure Score path)
- Some surfaces are **manual** (operator-confirmed) or **proxy** (Secure Score); see the check reference for per-check state
- Sentinel needs a **workspace ARM ID** + Azure RBAC
- Sign-in / MDE inventories may **truncate** on huge tenants
- Findings are **advisory**, not a compliance certification
- **No product telemetry** by default

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
