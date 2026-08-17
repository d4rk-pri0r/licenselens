---
hide:
  - navigation
  - toc
---

# Security License Lens

**The security you already own (and ignore).**

LicenseLens finds **Microsoft security configuration debt** — high-value
controls in E5, Entra ID P2, Defender, and related SKUs that you already pay
for but leave at default or unused. It maps owned entitlements to the controls
you should have on, and reports gaps as *you pay for X → expected Y → observed
Z*.

<div class="grid cards" markdown>

-   :material-rocket-launch-outline: **Quick start**

    ---

    Install, run the offline demo, and produce your first report in minutes.

    [:octicons-arrow-right-24: Get started](getting-started.md)

-   :material-security: **How it works**

    ---

    Entitlements, capabilities, checks, findings, and exit codes.

    [:octicons-arrow-right-24: Read the concepts](concepts.md)

-   :material-key-outline: **Live scans**

    ---

    App registration, auth modes, and the MSP batch workflow.

    [:octicons-arrow-right-24: Set up authentication](app-registration.md)

-   :material-shield-check-outline: **The check pack**

    ---

    140 declarative checks across identity, email, endpoint, and more.

    [:octicons-arrow-right-24: Browse the checks](checks.md)

</div>

## What it looks like

The report is a single, self-contained HTML file with a dark "Warm Charcoal"
theme, read top to bottom: posture, entitlements, ranked gaps with evidence,
and an explore view of every assessed control.

The opening section shows the tenant identity, the percentage of licensed
capability actually enforced, and the top recommended actions. Each capability
is labeled with its Microsoft workload icon, the capability field cross-filters
the page, and details expand in place with native disclosure. The report renders
with JavaScript disabled, makes no network requests, and honors
`prefers-reduced-motion`.

![The dashboard: what you own, what's working, and what to fix first.](images/report-hero.png)

Every finding shows its evidence and a direct link to the admin page.

![Every finding shows its evidence and a direct link to the admin page.](images/report-findings.png)

The same report is fully responsive and works offline at mobile width.

## The most common finding

`id-ca-priv-gaps`:

- **You pay for** Microsoft 365 E5, so Conditional Access is licensed for every user.
- **We expect** MFA and legacy-auth blocking enforced through a CA policy.
- **We observed** zero Conditional Access policies → the report marks the tenant `EXPOSED`.
- **Do this** → enable an MFA CA policy. The gap closes on the next scan.

## Why Security License Lens?

| Tool | Optimizes for |
|------|----------------|
| [ScubaGear](https://github.com/cisagov/ScubaGear) | CISA baseline compliance |
| [Maester](https://github.com/maester365/maester) | Continuous config tests (Pester) |
| Microsoft Secure Score | Score + recommendations (not SKU-gated) |
| License waste scripts | Seat assignment efficiency |
| **Security License Lens** | **Owned SKUs → expected high-value controls → unused/default gaps** |

[:material-book-open-page-variant-outline: Full comparison](comparison.md) ·
[:material-github: Source on GitHub](https://github.com/d4rk-pri0r/licenselens)
