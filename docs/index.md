---
hide:
  - navigation
  - toc
---

# Security License Lens

You already pay for Microsoft security features. A lot of them are still sitting at default.

LicenseLens looks at the SKUs in the tenant, maps them to the controls those SKUs are supposed to enable, then checks whether those controls are actually on. Findings look like: you pay for X, we expected Y, we observed Z.

<div class="grid cards" markdown>

-   :material-rocket-launch-outline: **Quick start**

    ---

    Install it, run the offline demo, open the HTML report.

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

    170 checks across identity, email, endpoint, and related workloads.
    Activation checks the paid security you already own; hygiene is an optional
    SCuBA-aligned pack.

    [:octicons-arrow-right-24: Browse the checks](checks.md)

</div>

<div markdown="1">

## Quick start

```bash
pipx install licenselens
licenselens demo
```

[![PyPI version](https://img.shields.io/pypi/v/licenselens)](https://pypi.org/project/licenselens/)
[![CI](https://img.shields.io/github/actions/workflow/status/d4rk-pri0r/licenselens/ci.yml?branch=main)](https://github.com/d4rk-pri0r/licenselens/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/licenselens)](https://pypi.org/project/licenselens/)

[:material-open-in-new: Try the sample report](sample-report.html)

## Install on your platform

- **View the sample report** — [:material-open-in-new: Open the interactive sample report](sample-report.html) — no install.
- **Windows** — `pipx install licenselens` then `licenselens demo` (or `licenselens quickstart`). Needs Python 3.12+ and pipx; see [prerequisites](windows.md#installing-the-cli-on-windows).
- **macOS / Linux** — `pipx install licenselens` then `licenselens demo`. Same commands as [quick start](#quick-start).

## What it looks like

One HTML file. Open it locally. It does not call home.

![The dashboard: what you own, what's working, and what to fix first.](images/report-hero.png)

![Every finding shows its evidence and a direct link to the admin page.](images/report-findings.png)

## The most common finding

`id-ca-priv-gaps`:

- **You pay for** Microsoft 365 E5, so Conditional Access is licensed for every user.
- **We expect** MFA and a block on legacy auth, enforced with a CA policy.
- **We observed** zero Conditional Access policies, so the tenant is marked `EXPOSED`.
- **Do this** — turn on an MFA CA policy. The gap closes on the next scan.

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
