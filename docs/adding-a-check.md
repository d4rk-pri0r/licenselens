# Adding a check

## 1. Ensure the capability exists

If the check depends on a licensed feature, add or reuse an entry in `catalog/capabilities.yaml`.

## 2. Create YAML

Path: `checks/<workload>/<id>.yaml`

```yaml
id: id-example
title: Short human title
description: >
  What paid capability should be realized, and what gap looks like.
workload: identity   # identity | defender | sentinel | purview | endpoint
required_capabilities:
  - entra_id_p2
severity: high       # critical | high | medium | low | info
value_impact: high   # high | medium | low
collector: graph_example
remediation: >
  Concrete next steps for an admin or consultant.
references:
  - https://learn.microsoft.com/...
enabled: true
```

## 3. Collector (optional in early PRs)

If logic is more than metadata, implement a collector and wire it in the engine. Until then, licensed checks may return `skipped`.

## 4. Test

- `licenselens checks` shows your check
- `pytest` passes
- Prefer fixtures over live tenants in CI

## 5. PR

Describe:

- Which SKU/plan unlocks the capability
- What “gap” means operationally
- Why MSPs/consultants care (security and/or value)
