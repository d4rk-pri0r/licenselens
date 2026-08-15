# Checks

Security License Lens ships **139 declarative checks** across ten workloads.
Each check is a single YAML file under `checks/<workload>/` and evaluates only
when its required capabilities are licensed.

## Workloads

| Workload | Checks | Examples |
|----------|-------:|----------|
| identity | 44 | Conditional Access gaps, PIM, dormant privileged accounts |
| collaboration | 22 | Teams federation, guest access, external sharing |
| defender | 21 | Safe Links / Safe Attachments, anti-spam, alert policies |
| exchange | 12 | SPF/DKIM/DMARC, forwarding, SMTP auth, mailbox audit |
| purview | 11 | DLP policy presence/enforcement, sensitivity labels, retention |
| endpoint | 8 | MDE onboard gaps, Intune policy |
| power-bi | 8 | Tenant settings, sharing |
| power-platform | 6 | DLP policies, environment isolation |
| sentinel | 5 | Analytics rule coverage, UEBA |
| azure | 2 | Azure resource hygiene |

## Check anatomy

Each check declares machine fields *and* customer-facing copy:

```yaml
id: id-ca-priv-gaps
title: Privileged sign-ins not strongly gated by Conditional Access
customer_title: Powerful accounts may sign in without strong extra checks
customer_summary: >
  You can require multi-factor authentication and block outdated sign-in methods.
  Gaps here mean admin or other high-value accounts might get in with weaker proof
  than your license already allows.
customer_next_step: >
  Require multi-factor authentication for admins and block legacy email sign-in
  methods that skip modern security prompts.
workload: identity
required_capabilities:
  - conditional_access
severity: high
impact: high
effort: hours
blast_radius: all_users
pack: identity
collector: graph_ca
remediation: >
  Create CA policies that require phishing-resistant MFA for privileged roles
  and block legacy authentication tenant-wide where possible.
references:
  - https://learn.microsoft.com/entra/identity/conditional-access/overview
  - https://learn.microsoft.com/entra/identity/conditional-access/block-legacy-authentication
enabled: true
```

## Field meanings

- **`severity`** — `critical` / `high` / `medium` / `low` / `info`.
- **`impact`** — `high` / `medium` / `low`.
- **`effort`** — `minutes` / `hours` / `days`; feeds the ranked fix list.
- **`blast_radius`** — who is affected: `all_users`, `admin`, `data`, `devices`.
- **`exposure_class`** — how a gap is surfaced (for example `none` for normal findings).
- **`collector`** — which [backend](collectors.md) supplies evidence.
- **`required_capabilities`** — the catalog entries that gate the check.

## Licensing gates

A check whose `required_capabilities` are not present reports `not_licensed`
instead of a gap. Unlicensed capabilities never produce false findings.

## Adding a check

See [Adding a check](adding-a-check.md) for the step-by-step guide and the
minimum bar for a new-check PR.
