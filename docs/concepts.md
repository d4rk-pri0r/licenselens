# Concepts

A short map of the model behind Security License Lens: entitlements,
capabilities, checks, findings, and the exit codes you'll see in CI.

## The core loop

```
Owned SKUs → capability catalog → eligible checks
        → collectors → findings → reports
```

1. **Entitlements.** The tenant's `subscribedSkus` and service plans are read
   from Microsoft Graph. Every SKU traces back to its parent, so the report can
   explain *which* entitlement licensed each capability.
2. **Capabilities.** `catalog/capabilities.yaml` maps service plans / SKU part
   numbers to product capabilities, each with plain-language `plain_name`,
   `outcome`, `why_it_matters`, and `if_unused` copy.
3. **Checks.** Declarative YAML under `checks/<workload>/` declares which
   capabilities a check needs and how to evaluate them. A check whose
   capabilities are not licensed reports `not_licensed` instead of a false gap.
4. **Collectors.** Read-only data sources (Graph, Defender for Endpoint, ARM,
   public DNS, Secure Score, and the Exchange Online PowerShell bridge) gather
   evidence. See [Collectors](collectors.md).
5. **Findings.** Each check yields a status plus customer-facing copy and an
   actionable next step.
6. **Reports.** Static HTML, JSON, and Markdown are written next to each other
   (flat under `-o` for `scan` / `demo` / `quickstart`; nested only for
   `batch`). See [CLI reference](cli.md).

## Finding statuses

Statuses match `FindingStatus` in the package models:

| Status | Meaning |
|--------|---------|
| `gap` | Licensed capability is off, unconfigured, or left at default. |
| `partial` | Partially configured; some of the expected control is missing. |
| `ok` | The expected control is in place. |
| `not_licensed` | You don't pay for the capability, so there is no gap. |
| `error` | The collector or evaluator failed; surfaced per-check, never silent. |
| `skipped` | Genuinely not evaluable with the available backend (not a false pass). |

## Evaluation modes

How a check obtains evidence (from the registry / schema contracts):

| Mode | Meaning |
|------|---------|
| `direct` | Reads the control itself from the preferred backend. |
| `proxy` | Infers from a neighboring signal (for example Secure Score); labeled and never treated as fully authoritative. |
| `manual` | Operator-confirmed; not fully automated. |
| `direct_with_proxy_fallback` | Tries direct evidence first; falls back to a labeled proxy only when direct is unavailable. |

Per-finding report rows still serialize the observed mode (`direct` or `proxy`)
when a dynamic check runs. Full flag catalog: [CLI reference](cli.md).

## Severity, impact, and effort

Every check declares its `severity` (`critical`/`high`/`medium`/`low`/`info`),
`impact` (`high`/`medium`/`low`), and `effort` (`minutes`/`hours`/`days`).
The engine ranks findings so the highest-value, lowest-effort fixes surface
first. Findings are **advisory** — they are not a compliance certification.

## Priority packs

Packs group checks by theme for ranking and the top card (`CheckPack`: identity,
email, endpoint, collaboration, power-platform, power-bi, starter). The default
priority packs are **identity + endpoint** (`DEFAULT_PACKS`); they shape the
headline rollup and top actions. Enabled checks still evaluate unless
`--workload` filters them.

Email is a **pack**, not a workload directory. Email policy config is not
readable via Graph (PowerShell-only). Use `--allow-email-proxy` only if you
explicitly want a labeled Secure Score degraded path — it never rolls up to
"fully working".

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (no gap/partial findings) |
| 1 | Completed with gap or partial findings |
| 2 | Auth / configuration / API error |

These make `licenselens scan` safe to gate a pipeline on: exit `1` means "there
is work to do", not "the tool failed". Command-level detail:
[CLI reference](cli.md).

## Where to go next

- [Quick start](getting-started.md) — first report in minutes
- [CLI reference](cli.md) — every command, flag, and env var
- [Checks](checks.md) — the full check pack
- [Architecture](architecture.md) — how the pieces fit together
