# Comparison with related tools

Security License Lens answers a different question than baseline scanners,
continuous config tests, CSPM suites, posture/vendor management tools, or
seat-waste scripts. It starts from owned SKUs, maps them to expected high-value
security controls, and reports **activation gaps** — capabilities an
organization already owns that are unused, on default, or incomplete — with
inspectable evidence.

## Tool-by-tool boundary

| Tool | Optimizes for | How LicenseLens differs |
|------|----------------|--------------------------|
| [ScubaGear](https://github.com/cisagov/ScubaGear) | CISA SCuBA baseline compliance | LicenseLens starts from owned SKUs → expected high-value controls, not a fixed baseline; both are advisory. |
| [Maester](https://github.com/maester365/maester) | Continuous Pester config tests | Maester tests specific settings you point it at; LicenseLens derives *which* controls to check from the entitlements you own. |
| Microsoft Secure Score | Numeric posture score + recommendations (not SKU-gated) | LicenseLens is entitlement-aware (what you own → activation gap) and exposes per-finding evidence; Secure Score is one labeled proxy path only when direct reads are unavailable. |
| [CIPP](https://github.com/KelvinTegelaar/CIPP) | MSP tenant administration & standard enforcement | CIPP is a management/automation platform; LicenseLens is a read-only activation assessment. Complementary: CIPP can remediate what LicenseLens identifies. |
| [Microsoft Lighthouse](https://learn.microsoft.com/microsoft-365/lighthouse/m365-lighthouse-overview) | Microsoft partner multi-tenant management | Lighthouse is a partner management surface; LicenseLens is an evidence-driven assessment with a repeatable activation backlog. |
| License waste scripts | Seat assignment efficiency | LicenseLens reports the *features* those seats unlock and whether they are actually operational, not just seat utilization. |
| **Security License Lens** | **Owned SKUs → expected high-value controls → evidence → activation gap** | The differentiation is the entitlement → capability → observed-evidence → gap relationship. |

## The differentiation

> **What the customer owns** + **what security capability that entitlement
> enables** + **what the tenant actually shows** = **activation gap**.

LicenseLens is **complementary** to Maester, CIPP, Lighthouse, and Secure Score,
not a replacement. It answers a question those tools do not centralize: "you pay
for X, so you should be able to use X — are you, and what does the tenant show
for it?" When direct evidence is unavailable for a surface, LicenseLens uses
Secure Score as a **labeled proxy path** (never treated as authoritative).
Findings are advisory, not a compliance certification, and LicenseLens does not
claim superiority over any listed tool without evidence.

## Where overlaps exist

Individual checks may overlap with the other tools (a Conditional Access MFA
check appears in Maester and SCuBA too). Overlap on a single control does not
make the products the same; what differs is the **contextual question** each
product optimizes and how it weighs entitlement.

