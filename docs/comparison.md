# Comparison with related tools

ScubaGear, Maester, Secure Score, CIPP, and license-waste scripts are all useful.
They answer different questions.

LicenseLens starts from the SKUs you already own, maps those SKUs to the
controls they unlock, then reports whether those controls are actually on. The
output is an activation gap with evidence, not a baseline score and not a
remediation platform.

## Tool-by-tool boundary

| Tool | Optimizes for | How LicenseLens differs |
|------|----------------|--------------------------|
| [ScubaGear](https://github.com/cisagov/ScubaGear) | CISA SCuBA baseline compliance | LicenseLens starts from owned SKUs → expected high-value controls, not a fixed baseline; both are advisory. |
| [Maester](https://github.com/maester365/maester) | Continuous Pester config tests | Maester tests specific settings you point it at; LicenseLens derives *which* controls to check from the entitlements you own. Complementary: ingest a Maester export with `licenselens ingest maester` to see which failures you already pay to fix. |
| Microsoft Secure Score | Numeric posture score + recommendations (not SKU-gated) | LicenseLens is entitlement-aware (what you own → activation gap) and exposes per-finding evidence; Secure Score is one labeled proxy path only when direct reads are unavailable. |
| [CIPP](https://github.com/KelvinTegelaar/CIPP) | MSP tenant administration & standard enforcement | CIPP is a management/automation platform; LicenseLens is a read-only activation assessment. Complementary: CIPP can remediate what LicenseLens identifies. |
| [Microsoft Lighthouse](https://learn.microsoft.com/microsoft-365/lighthouse/m365-lighthouse-overview) | Microsoft partner multi-tenant management | Lighthouse is a partner management surface; LicenseLens is an evidence-driven assessment with a repeatable activation backlog. |
| License waste scripts | Seat assignment efficiency | LicenseLens reports the *features* those seats unlock and whether they are actually operational, not just seat utilization. |
| **Security License Lens** | **Owned SKUs → expected high-value controls → evidence → activation gap** | The differentiation is the entitlement → capability → observed-evidence → gap relationship. |

## The question it answers

You pay for X, so you should be able to use X. Are you, and what does the tenant
show for it?

That is complementary to Maester, CIPP, Lighthouse, and Secure Score. It is not
a replacement. When LicenseLens cannot read a control directly, it may use
Secure Score as a labeled proxy. That path is never treated as the source of
truth.

Findings are advisory. This is not a compliance certification.

## Overlaps

A Conditional Access MFA check shows up in Maester and SCuBA too. Sharing a
control does not make the products the same. The difference is the question each
one is built to answer, and whether entitlement is part of that question.
