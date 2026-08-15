# Profiles and custom rules

Assessment profiles are declarative YAML files that shape *what* a scan looks
at, *which* backends it prefers, and *what* redaction settings the schema
accepts. They live under `catalog/profiles/` and validate against a JSON schema
(`catalog/profiles/assessment-profile.schema.json`) before any network call.

## Built-in profiles

| Profile | Scope |
|---------|-------|
| `core` | Default priority packs (identity + endpoint), no proxy. |
| `identity` | Entra ID controls, privileged access, and identity protection. |
| `full` | Every declarative area currently modeled by LicenseLens. |
| `email` | Exchange Online / MDO themed pack. |
| `collaboration` | SharePoint, OneDrive, and Teams sharing controls. |
| `endpoint` | Intune compliance, MDE onboarding, and endpoint baselines. |
| `data-protection` | Purview DLP, labels, retention, and related readiness checks. |
| `secops` | Sentinel analytics and UEBA-oriented checks. |
| `power-platform` | Power Platform tenant isolation and environment governance. |
| `power-bi` | Power BI external sharing and capacity governance. |
| `scuba` | Broad pack set aligned with SCuBA-oriented coverage. |

Authoritative pack/check expansion: [Profile reference](reference/profiles.md).

## Selecting a profile (`--profile` collision)

!!! warning "`--profile` means different things on `scan` vs `doctor`"

    On **`scan`**, **`demo`**, **`quickstart`**, and **`batch`**, `--profile`
    is an **assessment profile id** (`core`, `identity`, `full`, …).

    On **`doctor`**, `--profile` is **probe depth** only: `basic` (default,
    core Graph) or `full` (also MDE API + Sentinel). Assessment profiles on
    doctor use the separate, repeatable flag **`--assessment-profile`**.

```bash
# Assessment profile on scan
licenselens scan --profile identity -o reports
licenselens scan --live --auth client_secret --profile full -o reports

# Doctor: probe depth vs assessment requirements
licenselens doctor --live --profile full --auth client_secret
licenselens doctor --assessment-profile identity --assessment-profile full
```

Organization overlay or standalone rules without replacing the built-in id:

```bash
licenselens scan --config org-profile.yaml -o reports
licenselens scan --rules rules.yaml -o reports
licenselens scan --profile identity --config org-overlay.yaml --rules rules.yaml -o reports
```

## What a profile declares

- **`packs`** — the themed pack list for the top card and default scope.
- **`check_ids`** — an explicit check list, when a profile is prescriptive.
- **`backend_preferences`** — a `preferred` backend order (`graph`, `arm`,
  `exchange_online`, `defender`, `secure_score`, `manual`) plus `allow_proxy`
  and `allow_manual` flags.
- **`exclusions`** — accepted-risk waivers: `check_id`, `owner`, `reason`,
  `expires_on`, and an optional `kind: break_glass` with `principal_ids` for
  named emergency-access accounts.
- **`custom_rules`** — post-evaluation assertions over findings (see below).
- **`redaction`** — schema fields `redact_tenant_ids`, `redact_user_principals`,
  `redact_domains`, and a `replacement` token (see [Redaction](#redaction)).

## Custom rules

A custom rule asserts a condition over the finding set and is evaluated after
the scan. Each rule declares a `selector` (a finding field path such as
`finding.status` or `finding.severity`), an `operator` (`gte`, `in`, …), a
`value`, and optionally a `collection` (`count`) and `references`.

```yaml
custom_rules:
  - id: identity-high-gaps
    title: Identity high severity gaps
    selector: finding.severity
    operator: in
    value:
      - critical
      - high
    references:
      - https://learn.microsoft.com/security/zero-trust/deploy/identity
```

Supply standalone rules without a full profile via `--rules`:

```bash
licenselens scan --rules rules.yaml -o reports
```

## Exclusions and break-glass accounts

Exclusions let you document an accepted risk instead of pretending a finding is
"fixed". A break-glass exclusion records the named emergency-access principals
that are *meant* to skip all-user MFA, so the check can account for them rather
than flagging them as a gap.

## Redaction

`RedactionSettings` on the profile schema accepts `redact_tenant_ids`,
`redact_user_principals`, and `redact_domains` (plus `enabled` and
`replacement`). Those fields are validated and merged into the resolved profile,
but they are **NOT applied** to HTML, JSON, or Markdown reports today.

The only live UPN redaction in report evidence is the dormant-privileged
evaluator's local-part masking (`user@contoso.com` → `u***@contoso.com` in
dormant samples). Do not assume tenant IDs, domains, or other principals are
stripped from reports when profile redaction flags are true. Treat JSON/ZIP
artifacts as sensitive tenant data.

See [Permissions](permissions.md) for what each collector needs, and
[Architecture](architecture.md) for how profiles flow through the engine.
See [CLI reference](cli.md) for the full flag catalog.
