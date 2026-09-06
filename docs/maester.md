# Maester

Use Maester for deep configuration testing; use LicenseLens to know which
failures you are paying to fix.

Maester is a Pester suite that tests specific Microsoft 365 settings. LicenseLens
starts from the SKUs you already own and reports whether the controls those SKUs
unlock are actually on. The two tools overlap on some controls (for example
Conditional Access MFA) and answer different questions.

## Ingest a Maester export

After a LicenseLens scan and a Maester run (`Invoke-Maester -OutputJson`):

```bash
licenselens ingest maester maester.json --scan reports/security-license-lens-report.json -o reports
```

This writes a **side artifact** next to the scan:

- `security-license-lens-external-maester.json`
- `security-license-lens-external-maester.md`

Maester rows are **not** merged into the main findings list, so they never
change the posture figure or capability rollup.

## How mapping works

Maester tags that carry a SCuBA policy id (`MS.AAD.1.1v1`, and so on) are mapped
through `catalog/coverage/scuba-2026-08.yaml` to local check ids. Tests with no
SCuBA id are listed as unmapped and are not scored.

For each mapped Maester **failure**:

| Entitlement | Verdict |
|-------------|---------|
| Owned | You pay for the capability this test covers; Maester confirms the gap |
| Not in your plan | Maester flags this, but the enabling SKU is not detected — this is a licensing decision, not a configuration gap |

Disagreements are flagged for review:

- Maester fail vs LicenseLens ok
- LicenseLens gap vs Maester pass

Fields read from the Maester JSON: `Tests[].Name`, `Result`, `Tag`,
`ResultDetail.TestResult`.
