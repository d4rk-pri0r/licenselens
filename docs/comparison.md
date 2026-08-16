# Comparison with related tools

Security License Lens answers a different question than baseline scanners, continuous config tests, CSPM suites, Secure Score, or seat-waste scripts. It starts from **owned SKUs**, maps them to expected high-value controls, and reports unused or default gaps.

| Tool | Optimizes for |
|------|----------------|
| [ScubaGear](https://github.com/cisagov/ScubaGear) | CISA baseline compliance |
| [Maester](https://github.com/maester365/maester) | Continuous config tests (Pester) |
| Microsoft Secure Score | Score + recommendations (not SKU-gated) |
| License waste scripts | Seat assignment efficiency |
| **Security License Lens** | **Owned SKUs → expected high-value controls → unused/default gaps** |

## ScubaGear (CISA)

- **Optimizes for:** CISA baseline compliance (tenant settings vs SCuBA baselines)
- **LicenseLens differentiator:** Entitlement-gated “paid but unused” gaps, not a full baseline audit
- **Together?** Optional side-by-side; Scuba JSON import is not core

## Maester

- **Optimizes for:** Continuous config tests (Pester) for M365/Entra security config
- **LicenseLens differentiator:** SKU → capability → gap narrative for value + security posture
- **Together?** Run side-by-side; different questions

## Microsoft Secure Score

- **Optimizes for:** Score + recommendations (not SKU-gated)
- **LicenseLens differentiator:** Explicit mapping from **owned SKUs** to expected controls; portable offline HTML/JSON/Markdown
- **Note:** LicenseLens may use Secure Score as a labeled proxy path for some checks when direct evidence is unavailable

## License waste scripts

- **Optimizes for:** Seat assignment efficiency (who has which seats)
- **LicenseLens differentiator:** Whether **features those seats unlock** are configured and enforced

## Security License Lens

- **Optimizes for:** Owned SKUs → expected high-value controls → unused/default gaps
- Findings are **advisory**. LicenseLens is **not** a compliance certification.
