# Architecture

## Pipeline

```
Auth → Collectors → Entitlement resolution → Check selection → Findings → Reports
```

1. **Auth** — device code, client credentials, or Azure CLI (live mode TBD)
2. **Collectors** — Graph subscribed SKUs, then workload-specific config APIs
3. **Catalog** — maps service plans / SKU part numbers → capability IDs
4. **Engine** — loads YAML checks; marks `not_licensed` when capabilities missing
5. **Reports** — static HTML dashboard, JSON, Markdown

## Key types

- `SubscribedSku` / `ServicePlan` — tenant entitlements
- `Capability` — product feature unlocked by entitlements, plus plain-language
  `plain_name`, `outcome`, `why_it_matters`, `if_unused` for customer reports
- `CheckDefinition` — declarative check metadata, including `customer_title`,
  `customer_summary`, `customer_next_step`
- `Finding` — result with status `gap | partial | ok | not_licensed | error | skipped`
  and mirrored customer-facing fields
- `CapabilitySummary` — owned capabilities ready for the “What you already pay for” section
- `ScanResult` — full portable scan artifact, including `recommended_next_steps`

## Extensibility

- Add capabilities in `catalog/capabilities.yaml`
- Add checks as YAML under `checks/<workload>/`
- Implement collectors named in check `collector` fields
- Register pure evaluators in `engine/evaluate.py` (`EVALUATORS`)
- Keep reporting format stable so MSPs can archive JSON over time

## Data plane (v0.2)

| Evidence | API |
|----------|-----|
| SKUs | Graph `GET /subscribedSkus` |
| CA policies | Graph `GET /identity/conditionalAccess/policies` |
| Role assignments | Graph `GET /roleManagement/directory/roleAssignments` |
| PIM eligibility | Graph `GET /roleManagement/directory/roleEligibilitySchedules` |
| Sign-ins (bounded) | Graph `GET /auditLogs/signIns` |
| Principals | Graph `POST /directoryObjects/getByIds` |
| Secure Score | Graph `GET /security/secureScores` |
| MDE machines | `https://api.securitycenter.microsoft.com/api/machines` |
| Sentinel rules | ARM `.../Microsoft.SecurityInsights/alertRules` |
| Sentinel settings | ARM `.../Microsoft.SecurityInsights/settings` |
