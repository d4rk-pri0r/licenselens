# Profiles and custom rules

Assessment profiles are declarative YAML files that shape *what* a scan looks
at, *which* backends it prefers, and *what* it is allowed to redact or waive.
They live under `catalog/profiles/` and validate against a JSON schema
(`catalog/profiles/assessment-profile.schema.json`) before any network call.

## Built-in profiles

| Profile | Scope |
|---------|-------|
| `core` | Default priority packs (identity + endpoint), no proxy. |
| `identity` | Entra ID controls, privileged access, and identity protection. |
| `full` | Every declarative area currently modeled by LicenseLens. |
| `email`, `collaboration`, `endpoint`, `data-protection`, `secops`, `power-platform`, `power-bi`, `scuba` | Themed subsets. |

Pass one with `--assessment-profile <id>` (or `--profile` on `doctor`), or drop
a custom file with `--config`:

```bash
licenselens scan --assessment-profile identity -o reports
licenselens doctor --live --profile full --auth client_secret
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
- **`redaction`** — `redact_tenant_ids`, `redact_user_principals`,
  `redact_domains`, and a `replacement` token.

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

See [Permissions](permissions.md) for what each collector needs, and
[Architecture](architecture.md) for how profiles flow through the engine.
