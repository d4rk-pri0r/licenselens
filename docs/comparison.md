# Comparison with related tools

Security License Lens answers a different question than baseline scanners, continuous config tests, CSPM suites, Secure Score, or seat-waste scripts. It starts from owned SKUs, maps them to expected high-value controls, and reports unused or default gaps.

| Tool | Optimizes for |
|------|----------------|
| [ScubaGear](https://github.com/cisagov/ScubaGear) | CISA baseline compliance |
| [Maester](https://github.com/maester365/maester) | Continuous config tests (Pester) |
| Microsoft Secure Score | Score + recommendations (not SKU-gated) |
| License waste scripts | Seat assignment efficiency |
| **Security License Lens** | **Owned SKUs → expected high-value controls → unused/default gaps** |

ScubaGear checks tenant settings against CISA SCuBA baselines. Maester runs continuous Pester-based config tests across M365 and Entra. Microsoft Secure Score shows a numeric score plus improvement recommendations without regard to which SKUs you own. License-waste scripts report seat assignment efficiency, not whether the features those seats unlock are actually configured. LicenseLens takes the opposite path: it starts from SKUs you own, maps them to expected high-value controls, and flags the ones that stay unused or on default. When direct evidence isn't available for a check, LicenseLens may use Secure Score as a labeled proxy path. Findings are advisory, not a compliance certification.
