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
- `Capability` — product feature unlocked by entitlements
- `CheckDefinition` — declarative check metadata
- `Finding` — result with status `gap | partial | ok | not_licensed | error | skipped`
- `ScanResult` — full portable scan artifact

## Extensibility

- Add capabilities in `catalog/capabilities.yaml`
- Add checks as YAML under `checks/<workload>/`
- Implement collectors named in check `collector` fields
- Keep reporting format stable so MSPs can archive JSON over time
